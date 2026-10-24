import hashlib,json,io,os,logging,re,uuid,time
import httpx
from datetime import datetime,timezone,timedelta
from collections import Counter,defaultdict
from fastapi import FastAPI,Depends,HTTPException,UploadFile,File,Form,Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text,inspect
from PIL import Image
from app.config import CORS_ORIGINS, MAX_UPLOAD_BYTES, DEFAULT_STORE_RAW_CONTENT, RETENTION_DAYS, SAFE_BROWSING_API_KEY, GEMINI_MODEL
from app.database import Base,engine,get_db,SessionLocal
from app.models import ScanRecord,SystemSetting,AssistantConversationRecord,AssistantMessageRecord
from app.schemas import MessageAnalyzeRequest,URLAnalyzeRequest,AnalysisResult,DashboardAnalytics,SystemStatusResponse,PrivacySettingsPayload,MLAssessment,ThreatIntelResult,AssistantStatus,AssistantChatRequest,AssistantChatResponse,AssistantConversation,AssistantConversationSummary,AssistantMessage
from app.services.analyzer import analyze_text,analyze_url,score,redact,threat_result,assessment_basis,MODEL,MODEL_METADATA
from app.services.assistant import inspect_local_model,status_payload,generate_local_reply,SETUP_INSTRUCTIONS,redact_chat,curated_fallback_guidance,resolve_reply_language
from app.complaint_resources import COMPLAINT_RESOURCES
from app.services.language import SUPPORTED_LANGUAGES
logger=logging.getLogger('scamsathi.api')
app=FastAPI(title='ScamSathi API',version='1.0.0',description='Privacy-first scam analysis API. Scores are advisory, not guarantees.')
app.add_middleware(CORSMiddleware,allow_origins=CORS_ORIGINS,allow_credentials=False,allow_methods=['GET','POST','PUT','DELETE'],allow_headers=['Content-Type'],expose_headers=['Server-Timing'])
@app.middleware('http')
async def measure_assistant_request(request:Request,call_next):
 started=time.perf_counter();response=await call_next(request)
 if request.url.path=='/api/v1/assistant/chat':
  total_ms=(time.perf_counter()-started)*1000
  stages=getattr(request.state,'assistant_timings',{})
  response.headers['Server-Timing']=', '.join([f'{name};dur={value:.2f}' for name,value in stages.items()]+[f'total;dur={total_ms:.2f}'])
  logger.info('assistant_request_timing request_id=%s status=%s timings_ms=%s total_ms=%.2f',getattr(request.state,'assistant_request_id','-'),response.status_code,stages,total_ms)
 return response
@app.on_event('startup')
def startup():
 Base.metadata.create_all(bind=engine)
 columns={item['name'] for item in inspect(engine).get_columns('assistant_messages')}
 if 'client_request_id' not in columns:
  with engine.begin() as connection:
   connection.execute(text('ALTER TABLE assistant_messages ADD COLUMN client_request_id VARCHAR(36)'))
   connection.execute(text('CREATE INDEX IF NOT EXISTS ix_assistant_messages_client_request_id ON assistant_messages (client_request_id)'))
 with SessionLocal() as db:
  if not db.query(SystemSetting).filter_by(id=1).first(): db.add(SystemSetting(id=1,store_raw_content=DEFAULT_STORE_RAW_CONTENT,retention_days=RETENTION_DAYS));db.commit()
def get_settings(db):
 row=db.query(SystemSetting).filter_by(id=1).first()
 if not row: row=SystemSetting(id=1,store_raw_content=DEFAULT_STORE_RAW_CONTENT,retention_days=RETENTION_DAYS);db.add(row);db.commit();db.refresh(row)
 return row
def as_result(rec):
 d=json.loads(rec.details_json)
 basis=d.get('assessment_basis')
 if not basis:
  threat_data=d.get('threat_intel',{})
  if threat_data.get('verdict')=='malicious': basis='external_threat_match'
  elif any(item.get('severity') in ('critical','high') for item in d.get('rule_indicators',[])): basis='suspicious_pattern'
  elif d.get('rule_indicators'): basis='warning_signals'
  else: basis='insufficient_evidence'
 return AnalysisResult(scan_id=rec.id,scan_type=rec.scan_type,created_at=rec.created_at,redacted_preview=rec.redacted_preview,raw_content_stored=bool(rec.raw_content),extracted_text=d.get('extracted_text'),normalized_url=d.get('normalized_url'),risk_score=rec.risk_score,risk_level=rec.risk_level,assessment_basis=basis,scam_category=rec.scam_category,summary_explanation=d['summary_explanation'],recommended_actions=d['recommended_actions'],limitations_note=d['limitations_note'],ml_assessment=d['ml_assessment'],rule_indicators=d['rule_indicators'],threat_intel=d['threat_intel'],suspicious_spans=d.get('suspicious_spans',[]))
def save_scan(db,kind,content,indicators,spans,category,ml,normalized=None,extracted=None):
 threat=threat_result(normalized) if kind=='url' else threat_result(); total,level,summary,actions,limits=score(indicators,ml,threat,kind)
 setting=get_settings(db); digest=hashlib.sha256(content.encode('utf-8','replace')).hexdigest(); preview=redact(content)
 basis=assessment_basis(indicators,threat)
 details={'summary_explanation':summary,'recommended_actions':actions,'limitations_note':limits,'assessment_basis':basis,'ml_assessment':ml.model_dump(),'rule_indicators':[x.model_dump() for x in indicators],'threat_intel':threat.model_dump(),'suspicious_spans':spans,'normalized_url':normalized,'extracted_text':extracted}
 rec=ScanRecord(scan_type=kind,input_hash=digest,redacted_preview=preview,raw_content=content if setting.store_raw_content else None,risk_score=total,risk_level=level,scam_category=category,details_json=json.dumps(details));db.add(rec);db.commit();db.refresh(rec)
 logger.info('scan_saved id=%s type=%s level=%s indicators=%s model_status=%s',rec.id,kind,level,len(indicators),ml.status)
 return as_result(rec)
@app.get('/health')
def health(): return {'status':'ok','service':'ScamSathi API'}
@app.get('/api/v1/health')
def api_health(): return health()
@app.get('/api/v1/assistant/status',response_model=AssistantStatus)
async def assistant_status():
 return status_payload(await inspect_local_model())
@app.get('/api/v1/assistant/resources')
def assistant_resources(): return COMPLAINT_RESOURCES
@app.get('/api/v1/assistant/conversations',response_model=list[AssistantConversationSummary])
def assistant_conversations(limit:int=50,db:Session=Depends(get_db)):
 rows=db.query(AssistantConversationRecord).order_by(AssistantConversationRecord.updated_at.desc()).limit(max(1,min(limit,100))).all()
 return rows
@app.post('/api/v1/assistant/conversations',response_model=AssistantConversationSummary)
def create_assistant_conversation(db:Session=Depends(get_db)):
 row=AssistantConversationRecord(id=str(uuid.uuid4()),title='New conversation');db.add(row);db.commit();db.refresh(row);return row
@app.get('/api/v1/assistant/conversations/{conversation_id}',response_model=AssistantConversation)
def assistant_conversation(conversation_id:str,db:Session=Depends(get_db)):
 row=db.query(AssistantConversationRecord).filter_by(id=conversation_id).first()
 if not row: raise HTTPException(status_code=404,detail='Conversation not found.')
 messages=db.query(AssistantMessageRecord).filter_by(conversation_id=row.id).order_by(AssistantMessageRecord.id.asc()).limit(200).all()
 return {'id':row.id,'title':row.title,'created_at':row.created_at,'updated_at':row.updated_at,'messages':messages}
@app.delete('/api/v1/assistant/conversations/{conversation_id}')
def delete_assistant_conversation(conversation_id:str,db:Session=Depends(get_db)):
 row=db.query(AssistantConversationRecord).filter_by(id=conversation_id).first()
 if not row: raise HTTPException(status_code=404,detail='Conversation not found.')
 db.query(AssistantMessageRecord).filter_by(conversation_id=row.id).delete();db.delete(row);db.commit();return {'deleted':True,'conversation_id':conversation_id}

def _assistant_scan(db,payload):
 kind=payload.analysis_type
 content=(payload.content_to_analyze or '').strip()
 note='No scan was run; chat text is kept separate from scan content.'
 if kind=='none': return None,note
 if kind=='auto':
  # A standalone URL remains convenient to scan. Conversational text is never
  # treated as detector input; message scans require the separate field.
  if not content and re.fullmatch(r'(?i)(?:https?://|www\.)\S{3,2048}',payload.message.strip()):
   content=payload.message.strip();kind='url';note='Only the standalone URL in your message was scanned.'
  elif not content:
   return None,note
  elif re.fullmatch(r'(?i)(?:https?://|www\.)\S{3,2048}',content):
   kind='url';note='Only the separate scan-content field was analyzed.'
  else:
   kind='message';note='Only the separate scan-content field was analyzed.'
 else:
  if not content:
   return None,'No content was scanned. Paste the original suspicious message or URL into the separate scan-content field.'
  note='Only the separate scan-content field was analyzed.'
 if kind=='url':
  try: normalized,indicators,category=analyze_url(content)
  except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc))
  ml=MLAssessment(status='not_applicable',predicted_label='not_run',calibrated_probability=None,top_features=[],model_version=None,note='Text model is not applied to URLs.')
  return save_scan(db,'url',content,indicators,[x.matched_text for x in indicators if x.matched_text],category,ml,normalized=normalized),note
 indicators,spans,category,ml=analyze_text(content,payload.language_hint)
 return save_scan(db,'message',content,indicators,spans,category,ml),note

@app.post('/api/v1/assistant/chat',response_model=AssistantChatResponse)
async def assistant_chat(payload:AssistantChatRequest,request:Request,db:Session=Depends(get_db)):
 request.state.assistant_request_id=payload.client_request_id or '-'
 logger.info('assistant_request_start request_id=%s analysis_type=%s message_chars=%d',request.state.assistant_request_id,payload.analysis_type,len(payload.message))
 stored_user=redact_chat(payload.message,max_len=4000)
 existing_request=None
 if payload.client_request_id:
  try: uuid.UUID(payload.client_request_id)
  except ValueError: raise HTTPException(status_code=400,detail='Invalid client request id.')
  existing_request=db.query(AssistantMessageRecord).filter_by(client_request_id=payload.client_request_id).first()
  if existing_request: logger.info('assistant_idempotent_replay request_id=%s conversation_id=%s',payload.client_request_id,existing_request.conversation_id)
  if existing_request and (existing_request.role!='user' or existing_request.content!=stored_user):
   raise HTTPException(status_code=409,detail='This request id is already associated with another message.')
 if payload.conversation_id:
  try: uuid.UUID(payload.conversation_id)
  except ValueError: raise HTTPException(status_code=400,detail='Invalid conversation id.')
  conversation=db.query(AssistantConversationRecord).filter_by(id=payload.conversation_id).first()
  if not conversation: raise HTTPException(status_code=404,detail='Conversation not found. Start a new conversation.')
  if existing_request and existing_request.conversation_id!=conversation.id:
   raise HTTPException(status_code=409,detail='This request id belongs to a different conversation.')
 elif existing_request:
  conversation=db.query(AssistantConversationRecord).filter_by(id=existing_request.conversation_id).first()
  if not conversation: raise HTTPException(status_code=404,detail='Conversation not found. Start a new conversation.')
 else:
  conversation=AssistantConversationRecord(id=str(uuid.uuid4()),title='New conversation');db.add(conversation);db.commit();db.refresh(conversation)
 request.state.assistant_timings={}
 analysis=None
 if existing_request:
  analysis_note='Retry reused the existing request; no duplicate message or scanner operation was added.'
  later_messages=db.query(AssistantMessageRecord).filter(AssistantMessageRecord.conversation_id==conversation.id,AssistantMessageRecord.id>existing_request.id).order_by(AssistantMessageRecord.id.asc()).all()
  if any(item.role=='user' for item in later_messages):
   raise HTTPException(status_code=409,detail='A newer message exists in this conversation. Start a new request to continue.')
  saved_answer=next((item for item in later_messages if item.role=='assistant' and not item.content.startswith('[CURATED_SAFETY_GUIDANCE]\n')),None)
  if saved_answer:
   request.state.assistant_timings.update({'scanner':0.0,'history_context':0.0,'model_inference':0.0})
   return AssistantChatResponse(conversation_id=conversation.id,assistant_status='ready',assistant_reply=saved_answer.content,model=GEMINI_MODEL,setup_instructions=[],analysis=None,analysis_note=analysis_note,stored_redacted=True)
  request.state.assistant_timings['scanner']=0.0
 else:
  scan_started=time.perf_counter()
  try:
   analysis,analysis_note=_assistant_scan(db,payload)
  finally:
   request.state.assistant_timings['scanner']=(time.perf_counter()-scan_started)*1000
   logger.info('assistant_scanner_timing request_id=%s elapsed_ms=%.2f scanned=%s',payload.client_request_id or '-',request.state.assistant_timings['scanner'],analysis is not None)
  existing_request=AssistantMessageRecord(conversation_id=conversation.id,role='user',content=stored_user,client_request_id=payload.client_request_id)
  db.add(existing_request)
  if conversation.title=='New conversation': conversation.title=stored_user[:76] or 'New conversation'
  conversation.updated_at=datetime.now(timezone.utc);db.commit();db.refresh(existing_request)
 intent_started=time.perf_counter()
 safety=curated_fallback_guidance(payload.message,payload.language_hint)
 request.state.assistant_timings['intent_detection']=(time.perf_counter()-intent_started)*1000
 if safety:
  logger.info('assistant_fast_path request_id=%s source=%s title=%s language=%s',payload.client_request_id or '-',safety['source'],safety['title'],resolve_reply_language(payload.message,payload.language_hint))
  saved_reply='[CURATED_SAFETY_GUIDANCE]\n'+safety['text']
  if not existing_request or not db.query(AssistantMessageRecord).filter(AssistantMessageRecord.conversation_id==conversation.id,AssistantMessageRecord.id>existing_request.id,AssistantMessageRecord.content==saved_reply).first():
   db.add(AssistantMessageRecord(conversation_id=conversation.id,role='assistant',content=saved_reply))
   conversation.updated_at=datetime.now(timezone.utc);db.commit()
  request.state.assistant_timings.update({'history_context':0.0,'model_inference':0.0})
  return AssistantChatResponse(conversation_id=conversation.id,assistant_status='guidance',assistant_reply=None,model=None,setup_instructions=[],analysis=analysis,analysis_note=analysis_note,safety_guidance=safety,stored_redacted=True)
 history_started=time.perf_counter()
 recent=db.query(AssistantMessageRecord).filter(AssistantMessageRecord.conversation_id==conversation.id,AssistantMessageRecord.id<existing_request.id).order_by(AssistantMessageRecord.id.desc()).limit(4).all()
 context=[{'role':item.role,'content':item.content[:700]} for item in reversed(recent) if item.role in ('user','assistant') and not item.content.startswith('[CURATED_SAFETY_GUIDANCE]\n')]
 context.append({'role':'user','content':payload.message})
 if analysis:
  signs=', '.join(item.name for item in analysis.rule_indicators[:5]) or 'No known rule indicators matched.'
  context.insert(0,{'role':'system','content':f"Separate ScamSathi scan evidence (advisory, not proof): type={analysis.scan_type}; category={analysis.scam_category}; evidence score={analysis.risk_score}/100; level={analysis.risk_level}; basis={analysis.assessment_basis}; signals={signs}; URL reputation={analysis.threat_intel.verdict}. The original scan content is not included."})
 request.state.assistant_timings['history_context']=(time.perf_counter()-history_started)*1000
 logger.info('assistant_context_timing request_id=%s history_messages=%d prompt_messages=%d prompt_chars=%d elapsed_ms=%.2f',payload.client_request_id or '-',len(recent),len(context),sum(len(item['content']) for item in context),request.state.assistant_timings['history_context'])
 inference_started=time.perf_counter()
 state='error'
 try:
  generated=await generate_local_reply(context,resolve_reply_language(payload.message,payload.language_hint))
  if isinstance(generated,tuple): reply,model_timings=generated
  else: reply,model_timings=generated,{}
 except httpx.TimeoutException:
  request.state.assistant_timings['model_inference']=(time.perf_counter()-inference_started)*1000
  state='timeout'
 except httpx.HTTPStatusError as exc:
  logger.info('gemini_chat_http_status status=%s',exc.response.status_code)
  state='unavailable' if exc.response.status_code in (404,503) else 'error'
  request.state.assistant_timings['model_inference']=(time.perf_counter()-inference_started)*1000
 except (httpx.HTTPError,RuntimeError,ValueError) as exc:
  logger.info('gemini_chat_failed type=%s',type(exc).__name__)
  state='unavailable' if isinstance(exc,httpx.ConnectError) else 'error'
  request.state.assistant_timings['model_inference']=(time.perf_counter()-inference_started)*1000
 else:
  request.state.assistant_timings['model_inference']=(time.perf_counter()-inference_started)*1000
  if model_timings: request.state.assistant_timings.update({f'gemini_{key}':value for key,value in model_timings.items() if isinstance(value,(int,float))})
  safe_reply=redact_chat(reply,max_len=12000)
  db.add(AssistantMessageRecord(conversation_id=conversation.id,role='assistant',content=safe_reply))
  conversation.updated_at=datetime.now(timezone.utc);db.commit()
  return AssistantChatResponse(conversation_id=conversation.id,assistant_status='ready',assistant_reply=safe_reply,model=GEMINI_MODEL,setup_instructions=[],analysis=analysis,analysis_note=analysis_note,stored_redacted=True)
 return AssistantChatResponse(conversation_id=conversation.id,assistant_status=state,assistant_reply=None,model=None,setup_instructions=SETUP_INSTRUCTIONS,analysis=analysis,analysis_note=analysis_note,stored_redacted=True)

@app.post('/api/v1/analyze/message',response_model=AnalysisResult)
def message(payload:MessageAnalyzeRequest,db:Session=Depends(get_db)):
 indicators,spans,category,ml=analyze_text(payload.text,payload.language_hint);return save_scan(db,'message',payload.text,indicators,spans,category,ml)
@app.post('/api/v1/analyze/url',response_model=AnalysisResult)
def url(payload:URLAnalyzeRequest,db:Session=Depends(get_db)):
 try: normalized,indicators,category=analyze_url(payload.url)
 except ValueError as e: raise HTTPException(status_code=400,detail=str(e))
 ml=MLAssessment(status='not_applicable',predicted_label='not_run',calibrated_probability=None,top_features=[],model_version=None,note='Text model is not applied to URLs.')
 return save_scan(db,'url',payload.url,indicators,[x.matched_text for x in indicators if x.matched_text],category,ml,normalized=normalized)
@app.post('/api/v1/analyze/ocr',response_model=AnalysisResult)
async def ocr(file:UploadFile=File(...),manual_text:str=Form(''),db:Session=Depends(get_db)):
 data=await file.read(MAX_UPLOAD_BYTES+1)
 if len(data)>MAX_UPLOAD_BYTES: raise HTTPException(status_code=413,detail='Image exceeds the 5 MB upload limit.')
 if not data: raise HTTPException(status_code=400,detail='Please select an image file.')
 if len(manual_text)>10000: raise HTTPException(status_code=413,detail='Text exceeds the 10,000 character analysis limit.')
 mime=None
 if data[:8] == bytes([137,80,78,71,13,10,26,10]): mime='image/png'
 elif data[:3] == bytes([255,216,255]): mime='image/jpeg'
 elif data[:4]==b'RIFF' and data[8:12]==b'WEBP': mime='image/webp'
 if mime not in ('image/png','image/jpeg','image/webp'): raise HTTPException(status_code=400,detail='Only authentic PNG, JPEG, or WEBP images are accepted.')
 extracted=manual_text.strip()
 try:
  with Image.open(io.BytesIO(data)) as image:
   if image.format not in ('PNG','JPEG','WEBP'): raise ValueError('unexpected image format')
   if image.width * image.height > 20_000_000: raise HTTPException(status_code=413,detail='Image dimensions exceed the 20 megapixel limit.')
   image.verify()
 except HTTPException:
  raise
 except Exception:
  raise HTTPException(status_code=400,detail='The uploaded image is malformed or could not be decoded.')
 if not extracted:
  try:
   import pytesseract
   with Image.open(io.BytesIO(data)) as im: extracted=pytesseract.image_to_string(im.convert('L'),timeout=8).strip()
  except Exception: extracted=''
 if not extracted: raise HTTPException(status_code=422,detail='No readable text found. Install Tesseract or paste the screenshot text into the manual text field.')
 indicators,spans,category,ml=analyze_text(extracted);return save_scan(db,'ocr',extracted,indicators,spans,category,ml,extracted=extracted)
@app.get('/api/v1/history',response_model=list[AnalysisResult])
def history(limit:int=50,db:Session=Depends(get_db)):
 return [as_result(r) for r in db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(max(1,min(limit,200))).all()]
@app.delete('/api/v1/history/{scan_id}')
def delete_scan(scan_id:int,db:Session=Depends(get_db)):
 rec=db.query(ScanRecord).filter_by(id=scan_id).first()
 if not rec: raise HTTPException(status_code=404,detail='Scan record not found.')
 db.delete(rec);db.commit();return {'deleted':True,'scan_id':scan_id}
@app.get('/api/v1/dashboard',response_model=DashboardAnalytics)
def dashboard(db:Session=Depends(get_db)):
 records=db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).all(); levels=Counter(r.risk_level for r in records);cats=Counter(r.scam_category for r in records); days=defaultdict(lambda:{'date':'','scans':0,'high_risk':0})
 for r in records:
  dt=r.created_at.date().isoformat();days[dt]['date']=dt;days[dt]['scans']+=1;days[dt]['high_risk']+=int(r.risk_level in ('High','Critical'))
 return DashboardAnalytics(total_scans=len(records),high_or_critical_count=sum(levels[x] for x in ('High','Critical')),risk_distribution=[{'name':k,'value':v} for k,v in levels.items()],category_breakdown=[{'category':k,'count':v} for k,v in cats.most_common()],scans_over_time=[days[k] for k in sorted(days)],recent_scans=[as_result(r) for r in records[:8]],model_status={'status':'trained_demo' if MODEL is not None else 'untrained','disclaimer':'The small TF-IDF classifier is a development fixture; native-script messages are assessed by rules only, with no language-specific performance claim.','classifier_languages':['English','limited Romanized Hindi fixture examples']},threat_intel_configured=bool(SAFE_BROWSING_API_KEY))
@app.get('/api/v1/system/status',response_model=SystemStatusResponse)
def system_status(db:Session=Depends(get_db)):
 s=get_settings(db)
 try: import pytesseract; ocr=any(os.access(p,os.X_OK) for p in ['/usr/bin/tesseract','/opt/homebrew/bin/tesseract','/usr/local/bin/tesseract'])
 except Exception: ocr=False
 return SystemStatusResponse(api_status='operational',app_version='1.0.0',database_connected=True,ocr_engine_available=ocr,threat_intel_provider='Google Safe Browsing (optional; not queried in this build)',threat_intel_configured=bool(SAFE_BROWSING_API_KEY),model_metadata={'status':MODEL_METADATA.get('status','trained_demo') if MODEL is not None else 'untrained','model_version':MODEL_METADATA.get('model_version') if MODEL is not None else None,'classifier_languages':['en','limited Hinglish development examples'],'rule_processing_languages':sorted(SUPPORTED_LANGUAGES),'language_performance_validated':False,'disclaimer':'The TF-IDF classifier is a 24-row development fixture. Native-script languages use contextual rules only; language coverage does not imply measured detection performance.','metrics_heldout_test':MODEL_METADATA.get('test_metrics',{'rows':6,'accuracy':0.8333,'scam_recall':1.0,'scam_false_negative_rate':0.0,'benign_false_positive_rate':0.3333})},privacy_settings=PrivacySettingsPayload(store_raw_content=s.store_raw_content,retention_days=s.retention_days))
@app.put('/api/v1/system/settings',response_model=PrivacySettingsPayload)
def update_settings(payload:PrivacySettingsPayload,db:Session=Depends(get_db)):
 s=get_settings(db);s.store_raw_content=payload.store_raw_content;s.retention_days=payload.retention_days;db.commit();return payload
