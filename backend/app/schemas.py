from pydantic import BaseModel,Field,ConfigDict
from typing import Optional,Any,Literal
from datetime import datetime
class RuleIndicator(BaseModel): id:str; name:str; severity:str; description:str; matched_text:Optional[str]=None; weight:float
class MLAssessment(BaseModel): status:str; predicted_label:str; calibrated_probability:Optional[float]=None; top_features:list[str]=[]; model_version:Optional[str]=None; note:str; detected_language:Optional[str]=None; language_identification:Optional[str]=None
class ThreatIntelResult(BaseModel): provider:str; mode:str; verdict:str; details:str
class AnalysisResult(BaseModel):
 scan_id:int; scan_type:str; created_at:datetime; redacted_preview:str; raw_content_stored:bool; extracted_text:Optional[str]=None; normalized_url:Optional[str]=None
 risk_score:float=Field(ge=0,le=100); risk_level:str; assessment_basis:Literal['external_threat_match','suspicious_pattern','warning_signals','insufficient_evidence']='insufficient_evidence'; scam_category:str; summary_explanation:str; recommended_actions:list[str]; limitations_note:str
 ml_assessment:MLAssessment; rule_indicators:list[RuleIndicator]; threat_intel:ThreatIntelResult; suspicious_spans:list[str]=[]
class MessageAnalyzeRequest(BaseModel): text:str=Field(min_length=3,max_length=10000); language_hint:Optional[str]='auto'
class URLAnalyzeRequest(BaseModel): url:str=Field(min_length=4,max_length=2048)
class PrivacySettingsPayload(BaseModel): store_raw_content:bool; retention_days:int=Field(ge=1,le=365)
class DashboardAnalytics(BaseModel): total_scans:int; high_or_critical_count:int; risk_distribution:list[dict[str,Any]]; category_breakdown:list[dict[str,Any]]; scans_over_time:list[dict[str,Any]]; recent_scans:list[AnalysisResult]; model_status:dict[str,Any]; threat_intel_configured:bool
class SystemStatusResponse(BaseModel): api_status:str; app_version:str; database_connected:bool; ocr_engine_available:bool; threat_intel_provider:str; threat_intel_configured:bool; model_metadata:dict[str,Any]; privacy_settings:PrivacySettingsPayload
class ComplaintResource(BaseModel): id:str; name:str; url:str; jurisdiction:str; purpose:str; source_urls:list[str]; verified_on:str; official:bool=True
class AssistantStatus(BaseModel): model_config=ConfigDict(protected_namespaces=()); runtime:str; runtime_available:bool; model:str; model_available:bool; model_loaded:bool=False; ready:bool; setup_instructions:list[str]; resources:list[ComplaintResource]
class AssistantConversationSummary(BaseModel): model_config=ConfigDict(from_attributes=True); id:str; title:str; created_at:datetime; updated_at:datetime
class AssistantMessage(BaseModel): model_config=ConfigDict(from_attributes=True); id:int; role:Literal['user','assistant']; content:str; created_at:datetime
class AssistantConversation(BaseModel): id:str; title:str; created_at:datetime; updated_at:datetime; messages:list[AssistantMessage]
class AssistantChatRequest(BaseModel):
 model_config=ConfigDict(str_strip_whitespace=True)
 message:str=Field(min_length=1,max_length=4000)
 conversation_id:Optional[str]=Field(default=None,max_length=36)
 analysis_type:Literal['auto','message','url','none']='auto'
 content_to_analyze:Optional[str]=Field(default=None,max_length=10000)
 language_hint:Optional[Literal['en','hi','hinglish','bn','mr','te','ta','gu','ur','kn','ml','or','pa','as']]=None
 client_request_id:Optional[str]=Field(default=None,max_length=36)
class AssistantSafetyGuidance(BaseModel): title:str; text:str; source:Literal['curated_safety_rule']='curated_safety_rule'
class AssistantChatResponse(BaseModel): conversation_id:str; assistant_status:Literal['ready','unavailable','timeout','error','guidance']; assistant_reply:Optional[str]=None; model:Optional[str]=None; setup_instructions:list[str]=[]; analysis:Optional[AnalysisResult]=None; analysis_note:Optional[str]=None; safety_guidance:Optional[AssistantSafetyGuidance]=None; stored_redacted:bool=True
