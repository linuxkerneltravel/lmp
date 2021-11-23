use mysql;
select user, plugin from user; 
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'mysql';
flush privileges;
ALTER user 'root'@'localhost' IDENTIFIED BY '123456';

