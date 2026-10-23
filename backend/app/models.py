from datetime import datetime,timezone
from sqlalchemy import Integer,String,Float,DateTime,Text,Boolean
from sqlalchemy.orm import Mapped,mapped_column
from app.database import Base
class ScanRecord(Base):
 __tablename__='scan_records'
 id:Mapped[int]=mapped_column(Integer,primary_key=True,index=True)
 scan_type:Mapped[str]=mapped_column(String(32),index=True)
 input_hash:Mapped[str]=mapped_column(String(64),index=True)
 redacted_preview:Mapped[str]=mapped_column(String(300))
 raw_content:Mapped[str|None]=mapped_column(Text,nullable=True)
 risk_score:Mapped[float]=mapped_column(Float)
 risk_level:Mapped[str]=mapped_column(String(32),index=True)
 scam_category:Mapped[str]=mapped_column(String(100))
 details_json:Mapped[str]=mapped_column(Text)
 created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),index=True)
class SystemSetting(Base):
 __tablename__='system_settings'
 id:Mapped[int]=mapped_column(Integer,primary_key=True,default=1)
 store_raw_content:Mapped[bool]=mapped_column(Boolean,default=False)
 retention_days:Mapped[int]=mapped_column(Integer,default=30)

class AssistantConversationRecord(Base):
 __tablename__='assistant_conversations'
 id:Mapped[str]=mapped_column(String(36),primary_key=True)
 title:Mapped[str]=mapped_column(String(140),default='New conversation')
 created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),index=True)
 updated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),index=True)

class AssistantMessageRecord(Base):
 __tablename__='assistant_messages'
 id:Mapped[int]=mapped_column(Integer,primary_key=True,index=True)
 conversation_id:Mapped[str]=mapped_column(String(36),index=True)
 role:Mapped[str]=mapped_column(String(16))
 content:Mapped[str]=mapped_column(Text)
 client_request_id:Mapped[str|None]=mapped_column(String(36),nullable=True,index=True)
 created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),index=True)
