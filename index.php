<?php
/* ================= CONFIG ================= */
// ISI SENDIRI TOKEN & CHAT ID LU
$BOT_TOKEN = "ISI_TOKEN_LU_DI_SINI";
$CHAT_ID   = "-100XXXXXXXXXX";

/* ================= TELEGRAM FUNC ================= */
function tg($method, $data){
 global $BOT_TOKEN;
 $url = "https://api.telegram.org/bot$BOT_TOKEN/$method";
 $opt = [
  "http"=>[
   "method"=>"POST",
   "header"=>"Content-Type: application/json",
   "content"=>json_encode($data)
  ]
 ];
 return file_get_contents($url,false,stream_context_create($opt));
}

/* ================= API ================= */
if(isset($_GET['api'])){
 $api=$_GET['api'];
 $in=json_decode(file_get_contents("php://input"),true);

 // simpan user
 if($api=="login"){
  tg("sendMessage",[
   "chat_id"=>$GLOBALS['CHAT_ID'],
   "text"=>"USER|".$in['user']."|".time()
  ]);
  exit;
 }

 // kirim pesan
 if($api=="send"){
  tg("sendMessage",[
   "chat_id"=>$GLOBALS['CHAT_ID'],
   "text"=>"MSG|".$in['from']."|".$in['to']."|".$in['msg']."|".time()
  ]);
  exit;
 }

 // ambil pesan (parse dari getUpdates)
 if($api=="fetch"){
  $raw = json_decode(
    file_get_contents(
     "https://api.telegram.org/bot".$BOT_TOKEN."/getUpdates?limit=100"
    ), true
  );

  $out=[];
  foreach($raw["result"] as $u){
   $t=$u["message"]["text"]??"";
   if(strpos($t,"MSG|")===0){
    $p=explode("|",$t);
    if(
      ($p[1]==$_GET['me'] && $p[2]==$_GET['peer']) ||
      ($p[1]==$_GET['peer'] && $p[2]==$_GET['me'])
    ){
     $out[]=[
      "from"=>$p[1],
      "to"=>$p[2],
      "msg"=>$p[3],
      "time"=>$p[4]
     ];
    }
   }
  }
  echo json_encode($out);
  exit;
 }
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>TeleChat</title>
<style>
body{margin:0;font-family:sans-serif;background:#0f172a;color:#fff}
#login,#chat{height:100vh;display:none}
#login{display:flex;align-items:center;justify-content:center}
input,button{padding:10px;border-radius:6px;border:none}
button{background:#22c55e;font-weight:bold}
#chat{display:flex}
#left{width:30%;background:#020617;padding:10px}
#right{flex:1;display:flex;flex-direction:column}
#msgs{flex:1;overflow:auto;padding:10px}
.me{text-align:right}
.bubble{display:inline-block;padding:8px 12px;border-radius:10px;margin:4px;max-width:70%}
.me .bubble{background:#22c55e;color:#000}
.peer .bubble{background:#334155}
</style>
</head>
<body>

<div id="login">
 <div>
  <h2>TeleChat</h2>
  <input id="u" placeholder="username">
  <button onclick="login()">MASUK</button>
 </div>
</div>

<div id="chat">
 <div id="left">
  <h4>Chat</h4>
  <input id="peer" placeholder="username target">
  <button onclick="openChat()">Buka</button>
 </div>

 <div id="right">
  <div id="msgs"></div>
  <div style="display:flex;gap:5px;padding:10px">
   <input id="msg" placeholder="ketik..." style="flex:1">
   <button onclick="send()">➤</button>
  </div>
 </div>
</div>

<script>
let me=localStorage.user, peer="";

if(!me){login.style.display="flex"}
else{chat.style.display="flex"}

function login(){
 me=u.value;
 localStorage.user=me;
 fetch("?api=login",{method:"POST",body:JSON.stringify({user:me})});
 location.reload();
}

function openChat(){
 peer=document.getElementById("peer").value;
 load();
}

function send(){
 fetch("?api=send",{method:"POST",
  body:JSON.stringify({from:me,to:peer,msg:msg.value})
 });
 msg.value="";
}

function load(){
 fetch(`?api=fetch&me=${me}&peer=${peer}`)
 .then(r=>r.json()).then(d=>{
  msgs.innerHTML="";
  d.forEach(m=>{
   let div=document.createElement("div");
   div.className=m.from==me?"me":"peer";
   div.innerHTML=`<div class="bubble">${m.msg}</div>`;
   msgs.appendChild(div);
  });
  msgs.scrollTop=99999;
 });
}

setInterval(()=>peer&&load(),2000);
</script>
</body>
</html>
