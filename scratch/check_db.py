import os
from sqlmodel import Session, create_engine, select
from models.db.alert import LastAlert

# Setup DB
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./keep.db")
engine = create_engine(DATABASE_URL)

def check_duplicates():
    with Session(engine) as session:
        # Get all last alerts
        statement = select(LastAlert)
        results = session.exec(statement).all()
        
        print(f"Total LastAlert records: {len(results)}")
        
        # Check for fingerprints that appear more than once (though it's a PK)
        # Check for alerts with similar names or fields
        for alert in results:
            print(f"Fingerprint: {alert.fingerprint} | Name: {alert.alert_id} | TS: {alert.timestamp}")

if __name__ == "__main__":
    check_duplicates()
