package prom_core

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
)

type ProcMetrics struct {
	Max_records   int
	NowTime       float64
	mu            sync.Mutex
	OriginalValue map[string]interface{}
	Records       []OneRecord
}

type OneRecord struct {
	TimeStamp float64 `json:"timestamp"`
	State     string  `json:"state"`
	Durtion   float64 `json:"durtion"`
}

func (p *ProcMetrics) Getorigindata(originalvalue chan map[string]interface{}) {
	p.OriginalValue = <-originalvalue
}

func (p *ProcMetrics) processJson() OneRecord {
	timestamp := float64(0)
	state := ""
	durtion := float64(0)
	for key, value := range p.OriginalValue {
		if key == "flag" {
			if value.(string) == "1" {
				state = "offcpu"
			} else {
				state = "oncpu"
			}
		} else if key == "time" {
			durtion, _ = strconv.ParseFloat(value.(string), 64)
			p.NowTime = p.NowTime + durtion
			timestamp = p.NowTime
		} else {
			continue
		}
	}

	onerecord := OneRecord{TimeStamp: timestamp, State: state, Durtion: durtion}
	return onerecord
}

func (p *ProcMetrics) UpdateRecords() {
	log.Println(p.OriginalValue)
	if len(p.Records) < p.Max_records {
		p.Records = append(p.Records, p.processJson())
	} else {
		p.Records = append(p.Records, p.processJson())
		p.Records = p.Records[1:]
	}
}

func (p *ProcMetrics) GetRecordsJSON() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return json.Marshal(p.Records)
}

func (p *ProcMetrics) BootProcService() {
	go http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		recordsJson, err := p.GetRecordsJSON()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(recordsJson)
	})
	go func() {
		if err := http.ListenAndServe(":8090", nil); err != nil {
			log.Fatalf("Failed to start HTTP server:", err)
		}
	}()
	select {}
}
