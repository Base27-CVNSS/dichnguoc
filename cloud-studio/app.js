"use strict";
/* Dịch Ngược AI — public-source, read-only browser investigation.
   No credentials, arbitrary script execution, or remote REA/MCP calls. */
const $ = (id) => document.getElementById(id);
const limits = { files: 28, maxBytesPerFile: 120000, findings: 90 };
const rules = [
  { id:"node-integration", severity:"high", title:"Electron bật nodeIntegration", rx:/\bnodeIntegration\s*:\s*true\b/ },
  { id:"context-isolation", severity:"high", title:"Electron tắt contextIsolation", rx:/\bcontextIsolation\s*:\s*false\b/ },
  { id:"web-security", severity:"high", title:"Cấu hình tắt webSecurity", rx:/\bwebSecurity\s*:\s*false\b/ },
  { id:"insecure-content", severity:"high", title:"Cho phép nội dung không an toàn", rx:/\ballowRunningInsecureContent\s*:\s*true\b/ },
  { id:"eval", severity:"medium", title:"Thực thi mã động cần rà soát", rx:/\beval\s*\(|\bnew\s+Function\s*\(/ },
  { id:"shell", severity:"medium", title:"Thao tác shell/tiến trình", rx:/\b(?:execSync|spawnSync|execFileSync|execFile|spawn|exec)\s*\(/ },
  { id:"js-injection", severity:"medium", title:"Electron executeJavaScript", rx:/\bexecuteJavaScript\s*\(/ },
  { id:"ipc-main", severity:"info", title:"Electron IPC phía main", rx:/\bipcMain\.(?:on|once|handle)\s*\(/ },
  { id:"ipc-renderer", severity:"info", title:"Electron IPC phía renderer", rx:/\bipcRenderer\.(?:send|invoke|sendSync)\s*\(/ },
  { id:"context-bridge", severity:"info", title:"Electron contextBridge", rx:/\bcontextBridge\.exposeInMainWorld\s*\(/ },
  { id:"load-url", severity:"info", title:"Điểm tải URL của Electron", rx:/\bloadURL\s*\(/ }
];
let lastReport = null, activeScan = 0;
function setStatus(message,kind=""){ $("status").textContent=message; $("status").dataset.kind=kind; }
function showTab(name){
  for(const t of ["quick","cloud","ai"]){
    $("tab-"+t).classList.toggle("hidden", t!==name);
    $("btn-"+t).setAttribute("aria-selected",t===name?"true":"false");
  }
}
for (const btn of document.querySelectorAll("[data-tab]"))
  btn.addEventListener("click",()=>showTab(btn.dataset.tab));
function slugFromInput(value){
  let text=value.trim();
  if(text.startsWith("https://")){
    const url=new URL(text);
    if(url.hostname!=="github.com"||url.port||url.username||url.password||url.search||url.hash)
      throw new Error("Chỉ hỗ trợ URL repository github.com công khai.");
    text=url.pathname.replace(/^\/|\/$/g,"");
  }
  text=text.replace(/\.git$/i,"");
  const parts=text.split("/");
  if(parts.length!==2 || parts.some(p=>!(/^[a-zA-Z0-9_.-]+$/.test(p))||p==="."||p===".."||p.startsWith("-")||p.includes("..")))
    throw new Error("Nhập repository theo dạng owner/repository (không phải đường dẫn đến tệp).");
  return parts.join("/");
}
async function getJson(url){
  const response=await fetch(url,{headers:{"Accept":"application/vnd.github+json"}});
  if(!response.ok){
    if(response.status===404) throw new Error("Không tìm thấy kho công khai hoặc phiên bản Git.");
    if(response.status===403) throw new Error("GitHub API tạm giới hạn truy vấn. Thử lại sau.");
    throw new Error("Lỗi API GitHub: HTTP "+response.status);
  }
  return response.json();
}
function linkFor(slug,sha,path,line){
  return "https://github.com/"+slug+"/blob/"+sha+"/"+path.split("/").map(encodeURIComponent).join("/")+"#L"+line;
}
function rankFile(path){
  let score=0;
  if(/(^|\/)(main|preload|electron|ipc|background|index)\.[mc]?[jt]sx?$/i.test(path)) score+=60;
  if(/(^|\/)package\.json$/.test(path)) score+=50;
  if(/(^|\/)(src|app|electron)\//.test(path)) score+=15;
  if(/(^|\/)(test|tests|spec|fixtures|examples)\//.test(path)) score-=40;
  score-=path.split("/").length;
  return score;
}
function scanSource(text,path,slug,sha,findings,imports){
  const lines=text.split(/\r?\n/);
  for(let i=0;i<lines.length;i++){
    const line=lines[i];
    if(line.length>10000) continue;
    const dependency = /\b(?:from\s*|require\s*\(\s*|import\s*\(\s*)["']([^"']+)["']/.exec(line);
    if(dependency) imports.add(dependency[1]);
    // Approximate text-pattern matching, not full JS parsing or confirmed vulnerabilities.
    if(/^\s*(?:\/\/|\*|#)/.test(line)) continue;
    for(const rule of rules){
      if(findings.length>=limits.findings) return;
      if(rule.rx.test(line)){
        findings.push({
          id:rule.id, severity:rule.severity, title:rule.title,
          source:"static-regex", path, line:i+1,
          excerpt:line.trim().slice(0,240),
          url:linkFor(slug,sha,path,i+1),
          interpretation:"Dấu hiệu cần kiểm tra thêm; không tự khẳng định có lỗ hổng."
        });
      }
    }
  }
}
function promptFrom(report){
  const evidence=report.findings.slice(0,18).map(f=>"- ["+f.severity+"] "+f.title+" — "+f.path+":"+f.line+" "+f.url).join("\n");
  return [
    "Bạn là chuyên gia phân tích phần mềm và kiểm toán bảo mật theo phương pháp REA (Reverse Engineer Anything).",
    "Mục tiêu: làm rõ kiến trúc, modules, imports, luồng IPC Electron, trust boundaries và rủi ro cần xác minh.",
    "Repository: https://github.com/"+report.repo,
    "Commit: "+report.commit,
    "Quét tĩnh bằng trình duyệt: "+report.examinedFiles+"/"+report.totalFiles+" tệp được đọc, "+report.findings.length+" dấu hiệu.",
    "Bằng chứng bước đầu (đây là regex heuristic, KHÔNG phải kết quả REA):",
    evidence || "(không có dấu hiệu trong phạm vi mẫu đã quét)",
    "Giới hạn: "+report.limitations.join("; "),
    "Yêu cầu: (1) tách QUAN SÁT / SUY LUẬN / CHƯA RÕ; (2) trích tệp:dòng cho từng kết luận; ",
    "(3) phân biệt rủi ro thực tế và cảnh báo giả; (4) lập bảng chức năng, call graph/IPC nếu đủ dữ liệu; ",
    "(5) đưa kế hoạch kiểm chứng an toàn, không chạy mã không tin cậy. Nếu tôi đính kèm rea-output.json từ GitHub Actions, ưu tiên evidence JSON đó."
  ].join("\n");
}
function addText(parent,tag,value,cls){
  const e=document.createElement(tag); if(cls)e.className=cls;e.textContent=value;parent.append(e);return e;
}
function render(report){
  $("total").textContent=report.totalFiles.toLocaleString("vi-VN");
  $("inspected").textContent=report.examinedFiles.toLocaleString("vi-VN");
  $("count").textContent=String(report.findings.length);
  $("summary").textContent="Kho: "+report.repo+" · Commit "+report.commit.slice(0,12)+
    " · "+report.imports.length+" dependency được nhận diện; "+
    (report.truncatedTree?"GitHub trả về cây chưa đầy đủ. ":"")+
    "Đây là quét mẫu theo biểu thức chính quy, không phải REA đầy đủ.";
  const container=$("findings");container.replaceChildren();
  if(!report.findings.length) addText(container,"p","Không tìm thấy quy tắc khớp trong mẫu đã quét. Không có nghĩa là phần mềm an toàn.","muted");
  for(const item of report.findings.slice(0,60)){
    const card=document.createElement("article");card.className="finding";
    const header=document.createElement("header");
    addText(header,"span",item.severity.toUpperCase(),"severity "+item.severity);
    addText(header,"strong",item.title);card.append(header);
    addText(card,"small",item.path+":"+item.line+" · "+item.source);
    addText(card,"code",item.excerpt);
    const anchor=addText(card,"a","Xem bằng chứng trên GitHub ↗");anchor.href=item.url;
    anchor.target="_blank";anchor.rel="noopener noreferrer";
    container.append(card);
  }
  if(report.findings.length>60)addText(container,"p","Đang hiển thị 60/"+report.findings.length+" dấu hiệu. Tải JSON để xem đầy đủ.","muted");
  $("prompt").textContent=promptFrom(report);
  $("export").disabled=false;$("copy").disabled=false;
}
async function runScan(){
  const scanId=++activeScan;
  $("scan").disabled=true;$("export").disabled=true;$("copy").disabled=true;
  lastReport=null;$("findings").replaceChildren();$("summary").textContent="Đang khởi tạo...";
  for(const key of ["total","inspected","count"])$(key).textContent="—";
  try{
    const slug=slugFromInput($("repo").value);
    setStatus("Đang tải thông tin kho GitHub...","busy");
    const meta=await getJson("https://api.github.com/repos/"+slug);
    if(meta.private)throw new Error("Chế độ trình duyệt chỉ hỗ trợ kho công khai.");
    const commit=await getJson("https://api.github.com/repos/"+slug+"/commits/"+encodeURIComponent(meta.default_branch));
    const sha=commit.sha;
    const tree=await getJson("https://api.github.com/repos/"+slug+"/git/trees/"+sha+"?recursive=1");
    if(!Array.isArray(tree.tree))throw new Error("GitHub không trả về danh sách tệp hợp lệ.");
    const all=tree.tree.filter(f=>f.type==="blob");
    const candidates=all.filter(f=>
      (/\.(?:js|mjs|cjs|jsx|ts|tsx)$/i.test(f.path)||/(^|\/)package\.json$/.test(f.path))&&
      f.size<=limits.maxBytesPerFile&&
      !/(^|\/)(node_modules|dist|build|vendor|coverage|\.git)\//.test(f.path)
    ).sort((a,b)=>rankFile(b.path)-rankFile(a.path)).slice(0,limits.files);
    const findings=[],imports=new Set(),examined=[],skipped=[];
    let next=0;
    setStatus("Đang đọc "+candidates.length+" tệp mẫu, giới hạn "+limits.maxBytesPerFile/1000+" KB/tệp...","busy");
    await Promise.all(Array.from({length:Math.min(4,candidates.length)},async()=>{
      while(next<candidates.length){
        const f=candidates[next++];
        try{
          const path=f.path.split("/").map(encodeURIComponent).join("/");
          const res=await fetch("https://raw.githubusercontent.com/"+slug+"/"+sha+"/"+path);
          if(!res.ok)throw new Error("HTTP "+res.status);
          const text=await res.text();
          if(new Blob([text]).size>limits.maxBytesPerFile)throw new Error("Tệp vượt giới hạn");
          scanSource(text,f.path,slug,sha,findings,imports);examined.push(f.path);
        }catch(e){skipped.push({path:f.path,reason:String(e.message||e)});}
      }
    }));
    if(scanId!==activeScan)return;
    const report={
      schema:"dichnguoc-browser-evidence-v1",source:"browser-static-regex",repo:slug,
      repositoryUrl:"https://github.com/"+slug,commit:sha,generatedAt:new Date().toISOString(),
      totalFiles:all.length,truncatedTree:Boolean(tree.truncated),selectedFiles:candidates.length,
      examinedFiles:examined.length,examinedPaths:examined.sort(),skipped,
      imports:Array.from(imports).sort(),findings:findings.sort((a,b)=>({high:0,medium:1,info:2}[a.severity]-{high:0,medium:1,info:2}[b.severity])||a.path.localeCompare(b.path)||a.line-b.line),
      limitations:[
        "Lấy mẫu tối đa "+limits.files+" tệp và "+limits.maxBytesPerFile+" byte/tệp",
        "So khớp văn bản bằng regex; không phân tích AST/data-flow, không khẳng định lỗ hổng",
        "Chỉ repository GitHub công khai; không chạy chương trình",...(tree.truncated?["GitHub tree bị cắt ngắn"]:[])
      ]
    };
    lastReport=report;render(report);
    setStatus("Hoàn thành quét nhanh: "+report.examinedFiles+" tệp, "+report.findings.length+" dấu hiệu."+(skipped.length?" Bỏ qua "+skipped.length+" tệp.":""),"ok");
  }catch(e){if(scanId===activeScan)setStatus("Không thể hoàn tất: "+String(e.message||e),"error");}
  finally{if(scanId===activeScan)$("scan").disabled=false;}
}
async function copyText(value){
  try{await navigator.clipboard.writeText(value);setStatus("Đã sao chép vào bộ nhớ tạm.","ok");}
  catch{setStatus("Trình duyệt chặn clipboard. Hãy chọn văn bản và sao chép thủ công.","error");}
}
$("scan").addEventListener("click",runScan);
$("export").addEventListener("click",()=>{
  if(!lastReport)return;
  const blob=new Blob([JSON.stringify(lastReport,null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob),a=document.createElement("a");
  a.href=url;a.download="dichnguoc-"+lastReport.repo.replace("/","-")+"-"+lastReport.commit.slice(0,8)+".json";
  document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1200);
});
$("copy").addEventListener("click",()=>{if(lastReport)copyText(promptFrom(lastReport));});
$("copy-prompt").addEventListener("click",()=>copyText($("prompt").textContent));
$("open-actions").addEventListener("click",()=>window.open("https://github.com/Base27-CVNSS/dichnguoc/actions/workflows/rea-cloud.yml","_blank","noopener,noreferrer"));
$("copy-repo").addEventListener("click",()=>{
  try{copyText(slugFromInput($("repo").value));}catch(e){setStatus(String(e.message),"error");}
});

const cloudNav=document.querySelector('a[href="#workflow"]');
if(cloudNav)cloudNav.addEventListener('click',()=>showTab('cloud'));
