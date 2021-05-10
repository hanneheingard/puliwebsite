CREATE TABLE IF NOT EXISTS PULI_DB.TEXT(
ID INT AUTO_INCREMENT not null,
TEXT_GROUP VARCHAR(50) not null,
TEXT_KEY VARCHAR(50) not null,
TEXT TEXT not null,
PRIMARY KEY (ID))
;
INSERT INTO PULI_DB.TEXT (TEXT_GROUP, TEXT_KEY, TEXT) VALUES ('contact', 'name', 'Carina Karlsson');
INSERT INTO PULI_DB.TEXT (TEXT_GROUP, TEXT_KEY, TEXT) VALUES ('contact', 'number', '+46(0)708 48 75 02');
INSERT INTO PULI_DB.TEXT (TEXT_GROUP, TEXT_KEY, TEXT) VALUES ('contact', 'address', 'Slågarpsvägen 264-0 <br>Trelleborg - Sverige');
INSERT INTO PULI_DB.TEXT (TEXT_GROUP, TEXT_KEY, TEXT) VALUES ('aboutPuli', 'mainText', 'Det var en gång en puli...');