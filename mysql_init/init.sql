CREATE DATABASE IF NOT EXISTS loterie;
USE loterie;

CREATE TABLE utilisateur(
   id_utilisateur VARCHAR(50),
   mail VARCHAR(50) NOT NULL,
   pseudo VARCHAR(50),
   nom VARCHAR(50) NOT NULL,
   prenom VARCHAR(50) NOT NULL,
   adresse VARCHAR(100),
   cp CHAR(5),
   ville VARCHAR(50),
   telephone CHAR(10),
   role BOOLEAN,
   PRIMARY KEY(id_utilisateur),
   UNIQUE(mail)
);

CREATE TABLE Loterie(
   id_lotterie INT AUTO_INCREMENT,
   Montant VARCHAR(50),
   date_heure DATETIME,
   prix_billets DECIMAL(10,2),
   PRIMARY KEY(id_lotterie)
);

CREATE TABLE participer(
   id_utilisateur VARCHAR(50),
   id_lotterie INT,
   Cle_public VARCHAR(100) NOT NULL,
   Cle_prive VARCHAR(100) NOT NULL,
   PRIMARY KEY(id_utilisateur, id_lotterie),
   UNIQUE(Cle_public),
   UNIQUE(Cle_prive),
   FOREIGN KEY(id_utilisateur) REFERENCES utilisateur(id_utilisateur),
   FOREIGN KEY(id_lotterie) REFERENCES Loterie(id_lotterie)
);