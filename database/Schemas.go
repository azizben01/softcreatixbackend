package database

func GetTableQueries() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS services(
			name 			TEXT, 
			email 			TEXT, 
			phonenumber 	INT,
			services 		TEXT,
			Description 	TEXT,
			is_deleted 		BOOLEAN DEFAULT FALSE,
			id 				INT,
			status 			VARCHAR(20) DEFAULT 'pending'
	)`,
		`CREATE TABLE IF NOT EXISTS admin (
			adminid 		  SERIAL PRIMARY KEY,
			firstname         TEXT NOT NULL,
			lastname          TEXT NOT NULL,
			phonenumber		  INT  NOT NULL,
			password   		  TEXT NOT NULL,
			email	   		  TEXT NOT NULL,
			status     		  TEXT,
			resettoken        TEXT,
	        resettokenexpiry  TIMESTAMP WITH TIME ZONE
			
		)`,
	}
}
