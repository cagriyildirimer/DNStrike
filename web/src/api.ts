import type { CreateTestInput, DiscoveryProfile, Target, TargetInput, TestRun } from './types'

interface Envelope<T>{ data:T }
interface ErrorEnvelope{ error?:{ message?:string } }
async function request<T>(path:string, init?:RequestInit):Promise<T>{
  const response=await fetch(path,{...init,headers:{'Content-Type':'application/json',...init?.headers}})
  if(!response.ok){let body:ErrorEnvelope={};try{body=await response.json()}catch{/* non-json response */}throw new Error(body.error?.message??'İşlem tamamlanamadı.')}
  if(response.status===204)return undefined as T
  return ((await response.json()) as Envelope<T>).data
}
export const api={
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
