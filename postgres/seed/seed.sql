BEGIN TRANSACTION;

INSERT into users (name, email, entries, joined) values ('haha', 'haha@gmail.com', 5, '2018-01-01');
INSERT into login(hash, email) values ('$2a$10$OyEFJNi3DB2U99hum/lDv.6lTfkvpj/emkohOmDLwvuPtRIr0GyZu', 'haha@gmail.com');

COMMIT;