package sqlserver

import (
	"reflect"

	"gorm.io/gorm"
	"gorm.io/gorm/callbacks"
	"gorm.io/gorm/clause"
)

func Create(db *gorm.DB) {
	if db.Statement.Schema != nil && !db.Statement.Unscoped {
		for _, c := range db.Statement.Schema.CreateClauses {
			db.Statement.AddClause(c)
		}
	}

	if db.Statement.SQL.String() == "" {
		var (
			values                  = callbacks.ConvertToCreateValues(db.Statement)
			c                       = db.Statement.Clauses["ON CONFLICT"]
			onConflict, hasConflict = c.Expression.(clause.OnConflict)
		)

		if hasConflict {
			if len(db.Statement.Schema.PrimaryFields) > 0 {
				columnsMap := map[string]bool{}
				for _, column := range values.Columns {
					columnsMap[column.Name] = true
				}

				for _, field := range db.Statement.Schema.PrimaryFields {
					if _, ok := columnsMap[field.DBName]; !ok {
						hasConflict = false
					}
				}
			} else {
				hasConflict = false
			}
		}

		if hasConflict {
			MergeCreate(db, onConflict, values)
		} else {
			setIdentityInsert := false

			if field := db.Statement.Schema.PrioritizedPrimaryField; field != nil && field.AutoIncrement {
				switch db.Statement.ReflectValue.Kind() {
				case reflect.Struct:
					_, isZero := field.ValueOf(db.Statement.ReflectValue)
					setIdentityInsert = !isZero
				case reflect.Slice:
					for i := 0; i < db.Statement.ReflectValue.Len(); i++ {
						_, isZero := field.ValueOf(db.Statement.ReflectValue.Index(i))
						setIdentityInsert = !isZero
						break
					}
				}

				if setIdentityInsert {
					db.Statement.WriteString("SET IDENTITY_INSERT ")
					db.Statement.WriteQuoted(db.Statement.Table)
					db.Statement.WriteString(" ON;")
				}
			}

			db.Statement.AddClauseIfNotExists(clause.Insert{Table: clause.Table{Name: db.Statement.Table}})
			db.Statement.Build("INSERT")
			db.Statement.WriteByte(' ')

			db.Statement.AddClause(values)
			if values, ok := db.Statement.Clauses["VALUES"].Expression.(clause.Values); ok {
				if len(values.Columns) > 0 {
					db.Statement.WriteByte('(')
					for idx, column := range values.Columns {
						if idx > 0 {
							db.Statement.WriteByte(',')
						}
						db.Statement.WriteQuoted(column)
					}
					db.Statement.WriteByte(')')

					outputInserted(db)

					db.Statement.WriteString(" VALUES ")

					for idx, value := range values.Values {
						if idx > 0 {
							db.Statement.WriteByte(',')
						}

						db.Statement.WriteByte('(')
						db.Statement.AddVar(db.Statement, value...)
						db.Statement.WriteByte(')')
					}

					db.Statement.WriteString(";")
				} else {
					db.Statement.WriteString("DEFAULT VALUES;")
				}
			}

			if setIdentityInsert {
				db.Statement.WriteString("SET IDENTITY_INSERT ")
				db.Statement.WriteQuoted(db.Statement.Table)
				db.Statement.WriteString(" OFF;")
			}
		}
	}

	if !db.DryRun {
		rows, err := db.Statement.ConnPool.QueryContext(db.Statement.Context, db.Statement.SQL.String(), db.Statement.Vars...)

		if err == nil {
			defer rows.Close()

			if len(db.Statement.Schema.FieldsWithDefaultDBValue) > 0 {
				values := make([]interface{}, len(db.Statement.Schema.FieldsWithDefaultDBValue))

				switch db.Statement.ReflectValue.Kind() {
				case reflect.Slice, reflect.Array:
					var hasPrimaryValues, nonePrimaryValues []int
					for i := 0; i < db.Statement.ReflectValue.Len(); i++ {
						if _, isZero := db.Statement.Schema.PrioritizedPrimaryField.ValueOf(db.Statement.ReflectValue.Index(i)); isZero {
							nonePrimaryValues = append(nonePrimaryValues, i)
						} else {
							hasPrimaryValues = append([]int{i}, hasPrimaryValues...)
						}
					}
					nonePrimaryValues = append(nonePrimaryValues, hasPrimaryValues...)

					for rows.Next() {
						for idx, field := range db.Statement.Schema.FieldsWithDefaultDBValue {
							fieldValue := field.ReflectValueOf(db.Statement.ReflectValue.Index(nonePrimaryValues[db.RowsAffected]))
							values[idx] = fieldValue.Addr().Interface()
						}

						db.RowsAffected++
						db.AddError(rows.Scan(values...))
					}
				case reflect.Struct:
					for idx, field := range db.Statement.Schema.FieldsWithDefaultDBValue {
						values[idx] = field.ReflectValueOf(db.Statement.ReflectValue).Addr().Interface()
					}

					if rows.Next() {
						db.RowsAffected++
						db.AddError(rows.Scan(values...))
					}
				}
			}
		} else {
			db.AddError(err)
		}
	}
}

func MergeCreate(db *gorm.DB, onConflict clause.OnConflict, values clause.Values) {
	db.Statement.WriteString("MERGE INTO ")
	db.Statement.WriteQuoted(db.Statement.Table)
	db.Statement.WriteString(" USING (VALUES")
	for idx, value := range values.Values {
		if idx > 0 {
			db.Statement.WriteByte(',')
		}

		db.Statement.WriteByte('(')
		db.Statement.AddVar(db.Statement, value...)
		db.Statement.WriteByte(')')
	}

	db.Statement.WriteString(") AS excluded (")
	for idx, column := range values.Columns {
		if idx > 0 {
			db.Statement.WriteByte(',')
		}
		db.Statement.WriteQuoted(column.Name)
	}
	db.Statement.WriteString(") ON ")

	var where clause.Where
	for _, field := range db.Statement.Schema.PrimaryFields {
		where.Exprs = append(where.Exprs, clause.Eq{
			Column: clause.Column{Table: db.Statement.Table, Name: field.DBName},
			Value:  clause.Column{Table: "excluded", Name: field.DBName},
		})
	}
	where.Build(db.Statement)

	if len(onConflict.DoUpdates) > 0 {
		db.Statement.WriteString(" WHEN MATCHED THEN UPDATE SET ")
		onConflict.DoUpdates.Build(db.Statement)
	}

	db.Statement.WriteString(" WHEN NOT MATCHED THEN INSERT (")

	written := false
	for _, column := range values.Columns {
		if db.Statement.Schema.PrioritizedPrimaryField == nil || !db.Statement.Schema.PrioritizedPrimaryField.AutoIncrement || db.Statement.Schema.PrioritizedPrimaryField.DBName != column.Name {
			if written {
				db.Statement.WriteByte(',')
			}
			written = true
			db.Statement.WriteQuoted(column.Name)
		}
	}

	db.Statement.WriteString(") VALUES (")

	written = false
	for _, column := range values.Columns {
		if db.Statement.Schema.PrioritizedPrimaryField == nil || !db.Statement.Schema.PrioritizedPrimaryField.AutoIncrement || db.Statement.Schema.PrioritizedPrimaryField.DBName != column.Name {
			if written {
				db.Statement.WriteByte(',')
			}
			written = true
			db.Statement.WriteQuoted(clause.Column{
				Table: "excluded",
				Name:  column.Name,
			})
		}
	}

	db.Statement.WriteString(")")
	outputInserted(db)
	db.Statement.WriteString(";")
}

func outputInserted(db *gorm.DB) {
	if len(db.Statement.Schema.FieldsWithDefaultDBValue) > 0 {
		db.Statement.WriteString(" OUTPUT")
		for idx, field := range db.Statement.Schema.FieldsWithDefaultDBValue {
			if idx > 0 {
				db.Statement.WriteString(",")
			}
			db.Statement.WriteString(" INSERTED.")
			db.Statement.AddVar(db.Statement, clause.Column{Name: field.DBName})
		}
	}
}
