import type {AnalysisResult,AssistantChatResponse,AssistantConversation,AssistantConversationSummary,AssistantStatus,ComplaintResource,DashboardAnalytics,PrivacySettingsPayload,SystemStatusResponse} from '../types/api';
const API_BASE=(import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1').replace(/\/$/,'');
async function request<T>(path:string, init:RequestInit={}):Promise<T>{
 const isAssistantChat=path==='/assistant/chat';
 const started=performance.now();
 let responseStatus='network_error';
 let serverTiming:string|null=null;
 let requestId:string|undefined;
 if(isAssistantChat&&typeof init.body==='string'){
  try{requestId=JSON.parse(init.body).client_request_id}catch{/* Keep timing logs independent of request parsing. */}
 }
 if(isAssistantChat&&import.meta.env.DEV)console.info('[VEDVIQ AI] assistant_frontend_request_start',{requestId:requestId??'untracked'});
 try{
  let response:Response;
  try{response=await fetch(`${API_BASE}${path}`,init)}catch{throw new Error('Cannot connect to VEDVIQ AI. Start the backend at http://localhost:8000 and try again.')}
  responseStatus=String(response.status);
  serverTiming=response.headers.get('Server-Timing');
  if(!response.ok){let detail=`Request failed (${response.status})`;try{const body=await response.json();detail=body.detail||body.message||detail}catch{}throw new Error(detail)}
  return await response.json() as T;
 }finally{
  if(isAssistantChat&&import.meta.env.DEV){
   console.info('[VEDVIQ AI] assistant_frontend_request_timing',{requestId:requestId??'untracked',status:responseStatus,durationMs:Number((performance.now()-started).toFixed(2)),serverTiming});
  }
 }
}
export const api={
 analyzeMessage:(text:string)=>request<AnalysisResult>('/analyze/message',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})}),
 analyzeUrl:(url:string)=>request<AnalysisResult>('/analyze/url',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})}),
 analyzeOcr:(file:File,manualText:string)=>{const form=new FormData();form.append('file',file);form.append('manual_text',manualText);return request<AnalysisResult>('/analyze/ocr',{method:'POST',body:form})},
 getDashboard:()=>request<DashboardAnalytics>('/dashboard'),
 getHistory:()=>request<AnalysisResult[]>('/history'),
 deleteScan:(id:number)=>request<{deleted:boolean;scan_id:number}>(`/history/${id}`,{method:'DELETE'}),
 getSystemStatus:()=>request<SystemStatusResponse>('/system/status'),
 updateSettings:(settings:PrivacySettingsPayload)=>request<PrivacySettingsPayload>('/system/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(settings)}),
 getAssistantStatus:()=>request<AssistantStatus>('/assistant/status'),
 getAssistantResources:()=>request<ComplaintResource[]>('/assistant/resources'),
 getAssistantConversations:()=>request<AssistantConversationSummary[]>('/assistant/conversations'),
 getAssistantConversation:(id:string)=>request<AssistantConversation>(`/assistant/conversations/${encodeURIComponent(id)}`),
 createAssistantConversation:()=>request<AssistantConversationSummary>('/assistant/conversations',{method:'POST'}),
 deleteAssistantConversation:(id:string)=>request<{deleted:boolean;conversation_id:string}>(`/assistant/conversations/${encodeURIComponent(id)}`,{method:'DELETE'}),
 assistantChat:(payload:{message:string;conversation_id?:string;analysis_type:'auto'|'message'|'url'|'none';content_to_analyze?:string;language_hint?:string;client_request_id?:string})=>request<AssistantChatResponse>('/assistant/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
};
