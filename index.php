<?php
$db=new PDO("sqlite:data.db");
$db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);

/* ==== DB ==== */
$db->exec("
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY,
 username TEXT UNIQUE,
 name TEXT,
 bio TEXT
);

CREATE TABLE IF NOT EXISTS friends(
 from_u TEXT,
 to_u TEXT,
 status TEXT
);

CREATE TABLE IF NOT EXISTS messages(
 id INTEGER PRIMARY KEY,
 sender TEXT,
 target TEXT,
 type TEXT,
 content TEXT,
 time INTEGER
);

CREATE TABLE IF NOT EXISTS groups(
 id INTEGER PRIMARY KEY,
 name TEXT,
 owner TEXT
);

CREATE TABLE IF NOT EXISTS group_members(
 gid INTEGER,
 username TEXT
);
");

/* ==== API ==== */
if(isset($_GET['api'])){
 header("Content-Type: application/json");
 $in=json_decode(file_get_contents("php://input"),true);

 /* REGISTER */
 if($_GET['api']=="reg"){
  $db->prepare("INSERT OR IGNORE INTO users VALUES(NULL,?,?,?)")
     ->execute([$in['u'],$in['n'],$in['b']]);
  echo json_encode(["ok"=>1]); exit;
 }

 /* FRIEND REQUEST */
 if($_GET['api']=="addfriend"){
  $db->prepare("INSERT INTO friends VALUES(?,?,?)")
     ->execute([$in['from'],$in['to'],"pending"]);
  echo json_encode(["ok"=>1]); exit;
 }

 if($_GET['api']=="respond"){
  $db->prepare("UPDATE friends SET status=? WHERE from_u=? AND to_u=?")
     ->execute([$in['res'],$in['from'],$in['to']]);
  echo json_encode(["ok"=>1]); exit;
 }

 /* FRIEND LIST */
 if($_GET['api']=="friends"){
  $q=$db->prepare("SELECT * FROM friends WHERE to_u=? AND status='pending'");
  $q->execute([$_GET['u']]);
  echo json_encode($q->fetchAll(PDO::FETCH_ASSOC)); exit;
 }

 /* SEND MSG / FILE */
 if($_GET['api']=="send"){
  $db->prepare("INSERT INTO messages VALUES(NULL,?,?,?,?,?)")
     ->execute([$in['from'],$in['to'],$in['type'],$in['msg'],time()]);
  echo json_encode(["ok"=>1]); exit;
 }

 /* FETCH CHAT */
 if($_GET['api']=="fetch"){
  $q=$db->prepare("SELECT * FROM messages WHERE target=? ORDER BY time ASC");
  $q->execute([$_GET['t']]);
  echo json_encode($q->fetchAll(PDO::FETCH_ASSOC)); exit;
 }

 /* GROUP */
 if($_GET['api']=="newgroup"){
  $db->prepare("INSERT INTO groups VALUES(NULL,?,?)")
     ->execute([$in['name'],$in['owner']]);
  $gid=$db->lastInsertId();
  $db->prepare("INSERT INTO group_members VALUES(?,?)")
     ->execute([$gid,$in['owner']]);
  echo json_encode(["gid"=>$gid]); exit;
 }

 if($_GET['api']=="joingroup"){
  $db->prepare("INSERT INTO group_members VALUES(?,?)")
     ->execute([$in['gid'],$in['u']]);
  echo json_encode(["ok"=>1]); exit;
 }

 exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Veil</title>
<style>
body{margin:0;background:#0f172a;color:#fff;font-family:sans-serif}
.page{display:none}
.active{display:block}
.b{padding:8px;border-radius:10px;margin:5px}
.me{background:#2563eb;margin-left:auto}
.you{background:#334155}
</style>
</head>
<body>

<div id="login" class="page active">
<h3>Register</h3>
<input id="u" placeholder="username">
<button onclick="reg()">Go</button>
</div>

<div id="app" class="page">
<h3 id="title"></h3>
<div id="box" style="height:60vh;overflow:auto"></div>
<input id="text">
<input type="file" id="file">
<button onclick="send()">Send</button>

<hr>
<button onclick="newGroup()">New Group</button>
<button onclick="checkReq()">Friend Request</button>
</div>

<script>
let me=null, target=null;

function reg(){
 me=u.value;
 fetch('?api=reg',{method:'POST',body:JSON.stringify({u:me,n:me,b:''})});
 show('app');
}

function show(p){
 document.querySelectorAll('.page').forEach(x=>x.classList.remove('active'));
 document.getElementById(p).classList.add('active');
}

function openChat(t){
 target=t;
 title.innerText=t;
 load();
 setInterval(load,2000);
}

function load(){
 if(!target)return;
 fetch(`?api=fetch&t=${target}`)
 .then(r=>r.json()).then(d=>{
  box.innerHTML='';
  d.forEach(m=>{
   let div=document.createElement('div');
   div.className='b '+(m.sender==me?'me':'you');
   if(m.type=='file'){
     let a=document.createElement('a');
     a.href=m.content; a.download="file";
     a.innerText="📎 File";
     div.appendChild(a);
   }else div.innerText=atob(m.content);
   box.appendChild(div);
  });
 });
}

function send(){
 if(file.files[0]){
  let r=new FileReader();
  r.onload=()=>{
   fetch('?api=send',{method:'POST',body:JSON.stringify({
    from:me,to:target,type:'file',msg:r.result
   })});
  };
  r.readAsDataURL(file.files[0]);
 }else{
  fetch('?api=send',{method:'POST',body:JSON.stringify({
   from:me,to:target,type:'text',msg:btoa(text.value)
  })});
 }
 text.value='';
}

function newGroup(){
 let n=prompt("Group name");
 fetch('?api=newgroup',{method:'POST',body:JSON.stringify({name:n,owner:me})})
 .then(r=>r.json()).then(j=>openChat("group_"+j.gid));
}

function checkReq(){
 fetch('?api=friends&u='+me)
 .then(r=>r.json()).then(d=>{
  d.forEach(f=>{
   if(confirm("Accept "+f.from_u+"?")){
    fetch('?api=respond',{method:'POST',body:JSON.stringify({
     from:f.from_u,to:me,res:'accepted'
    })});
   }
  });
 });
}
</script>
</body>
</html>
