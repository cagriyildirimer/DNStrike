import type { CreateTestInput, DiscoveryProfile, Target, TargetInput, TestRun } from './types'

interface Envelope<T>{ data:T }
interface ErrorEnvelope{ error?:{ message?:string } }
export const unauthorizedEvent = 'dnstrike:unauthorized'

async function request<T>(path:string, init?:RequestInit, notifyUnauthorized=true):Promise<T>{
  const response=await fetch(path,{...init,credentials:'same-origin',headers:{'Content-Type':'application/json',...init?.headers}})
  if(response.status===401&&notifyUnauthorized)window.dispatchEvent(new Event(unauthorizedEvent))
  if(!response.ok){let body:ErrorEnvelope={};try{body=await response.json()}catch{/* non-json response */}throw new Error(body.error?.message??'İşlem tamamlanamadı.')}
  if(response.status===204)return undefined as T
  return ((await response.json()) as Envelope<T>).data
}
export const api={
  session:()=>request<{authenticated:boolean}>('/api/auth/session',undefined,false),
  login:(apiKey:string)=>request<{authenticated:boolean;expires_at:string}>('/api/auth/session',{method:'POST',body:JSON.stringify({api_key:apiKey})},false),
  logout:()=>request<void>('/api/auth/session',{method:'DELETE'}),
  listTargets:()=>request<Target[]>('/api/targets'),
  createTarget:(input:TargetInput)=>request<Target>('/api/targets',{method:'POST',body:JSON.stringify(input)}),
  deleteTarget:(id:number)=>request<void>(`/api/targets/${id}`,{method:'DELETE'}),
  discoverTarget:(id:number)=>request<DiscoveryProfile>(`/api/targets/${id}/check`,{method:'POST'}),
  listTests:()=>request<TestRun[]>('/api/tests'),
  getTest:(id:number)=>request<TestRun>(`/api/tests/${id}`),
  deleteTest:(id:number)=>request<void>(`/api/tests/${id}`,{method:'DELETE'}),
  createTest:(input:CreateTestInput)=>request<TestRun>('/api/tests',{method:'POST',body:JSON.stringify(input)}),
  listScenarios:()=>request<import('./types').ScenarioMetadata[]>('/api/scenarios')
}
