import * as THREE from 'three';

/* ============ cursor ============ */
const cursor = document.getElementById('cursor');
window.addEventListener('mousemove', e=>{
  cursor.style.left = e.clientX+'px'; cursor.style.top = e.clientY+'px';
});
document.querySelectorAll('.cta').forEach(el=>{
  el.addEventListener('mouseenter', ()=> cursor.classList.add('hover'));
  el.addEventListener('mouseleave', ()=> cursor.classList.remove('hover'));
});

/* ============ reduced motion / perf fallback ============ */
const REDUCE = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ============ three.js scene ============ */
const stage = document.getElementById('stage');
const scene = new THREE.Scene();
scene.fog = new THREE.FogExp2(0x050607, 0.035);
const camera = new THREE.PerspectiveCamera(50, innerWidth/innerHeight, 0.1, 200);
const renderer = new THREE.WebGLRenderer({ antialias:true, alpha:false });
renderer.setSize(innerWidth, innerHeight);
renderer.setPixelRatio(Math.min(devicePixelRatio, REDUCE?1:2));
renderer.setClearColor(0x050607);
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.15;
stage.appendChild(renderer.domElement);

scene.add(new THREE.AmbientLight(0x666666, 0.55));
const key = new THREE.DirectionalLight(0xffffff, 1.0);
key.position.set(6,8,6);
scene.add(key);
const rim = new THREE.PointLight(0xB08D57, 1.4, 34);
rim.position.set(-6,3,-4);
scene.add(rim);
const rim2 = new THREE.PointLight(0x6E8574, 0.9, 30);
rim2.position.set(5,-4,-6);
scene.add(rim2);

/* ---- distant twinkling starfield (depth/scale, not the artefact nodes) ---- */
const STAR_N = 500;
const starPos = new Float32Array(STAR_N*3);
for(let i=0;i<STAR_N;i++){
  const r = 40 + Math.random()*60;
  const a = Math.random()*Math.PI*2, b = Math.acos((Math.random()*2)-1);
  starPos[i*3]   = r*Math.sin(b)*Math.cos(a);
  starPos[i*3+1] = r*Math.sin(b)*Math.sin(a);
  starPos[i*3+2] = r*Math.cos(b) - 20;
}
const starGeo = new THREE.BufferGeometry();
starGeo.setAttribute('position', new THREE.BufferAttribute(starPos,3));
const starMat = new THREE.PointsMaterial({ color:0x8a8d94, size:0.06, transparent:true, opacity:0.5, sizeAttenuation:true });
const stars = new THREE.Points(starGeo, starMat);
scene.add(stars);

/* ---- Moment 1/2: primary node network — gold/silver sparkle stars ---- */
const N = 460;
const nodePos = [];
const nodeFail = [];
for(let i=0;i<N;i++){
  const v = new THREE.Vector3(
    (Math.random()-0.5)*40,   // wide horizontally — no visible left/right edge
    (Math.random()-0.5)*20,
    (Math.random()-0.5)*36 - 6
  );
  nodePos.push(v);
  nodeFail.push(Math.random() < 0.32); // "fail" nodes render gold (flagged), rest silver
}

// draw a 4-point sparkle/star with a soft glow core, once, onto a canvas texture
function makeSparkleTexture(){
  const size = 128, c = document.createElement('canvas');
  c.width = c.height = size;
  const ctx = c.getContext('2d');
  const cx = size/2, cy = size/2;
  const glow = ctx.createRadialGradient(cx,cy,0,cx,cy,size/2);
  glow.addColorStop(0,'rgba(255,255,255,1)');
  glow.addColorStop(0.25,'rgba(255,255,255,0.55)');
  glow.addColorStop(1,'rgba(255,255,255,0)');
  ctx.fillStyle = glow; ctx.fillRect(0,0,size,size);
  ctx.strokeStyle = 'rgba(255,255,255,0.9)'; ctx.lineWidth = 2; ctx.lineCap='round';
  ctx.beginPath(); ctx.moveTo(cx,4); ctx.lineTo(cx,size-4); ctx.moveTo(4,cy); ctx.lineTo(size-4,cy); ctx.stroke();
  ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(cx-size*0.22,cy-size*0.22); ctx.lineTo(cx+size*0.22,cy+size*0.22);
  ctx.moveTo(cx+size*0.22,cy-size*0.22); ctx.lineTo(cx-size*0.22,cy+size*0.22); ctx.stroke();
  return new THREE.CanvasTexture(c);
}
const sparkleTex = makeSparkleTexture();

const GOLD = new THREE.Color(0xF2C879);
const SILVER = new THREE.Color(0xDCE3E8);
const DIM = new THREE.Color(0x3f4248);

const nodeSprites = [];
const networkGroup = new THREE.Group();
for(let i=0;i<N;i++){
  const mat = new THREE.SpriteMaterial({ map:sparkleTex, color:DIM.clone(), transparent:true, opacity:0.35, blending:THREE.AdditiveBlending, depthWrite:false });
  const spr = new THREE.Sprite(mat);
  spr.position.copy(nodePos[i]);
  const base = 0.16 + Math.random()*0.09;
  spr.scale.setScalar(base);
  spr.userData = { base, phase:Math.random()*Math.PI*2, flash:0, target:DIM, targetOp:0.35 };
  networkGroup.add(spr);
  nodeSprites.push(spr);
}
function setNodeState(i, state){ // 'dim' | 'safe' | 'fail'
  const s = nodeSprites[i].userData;
  if(state==='dim'){ s.target = DIM; s.targetOp = 0.35; }
  else if(state==='safe'){ s.target = SILVER; s.targetOp = 1; }
  else { s.target = GOLD; s.targetOp = 1; }
}

const edgePos = [];
const edgeSeen = new Set();
const K = 3; // each star links to its 3 nearest neighbors — guarantees one connected web, no isolated clusters
for(let i=0;i<N;i++){
  const dists = [];
  for(let j=0;j<N;j++){ if(j!==i) dists.push([nodePos[i].distanceTo(nodePos[j]), j]); }
  dists.sort((a,b)=>a[0]-b[0]);
  for(let k=0;k<K;k++){
    const j = dists[k][1];
    const key = i<j ? i+'_'+j : j+'_'+i;
    if(edgeSeen.has(key)) continue;
    edgeSeen.add(key);
    edgePos.push(nodePos[i].x,nodePos[i].y,nodePos[i].z, nodePos[j].x,nodePos[j].y,nodePos[j].z);
  }
}
const edgeGeo = new THREE.BufferGeometry();
edgeGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(edgePos),3));
const edgeMat = new THREE.LineBasicMaterial({ color:0x4a4640, transparent:true, opacity:0.5 });
const edgeMesh = new THREE.LineSegments(edgeGeo, edgeMat);
networkGroup.add(edgeMesh);
scene.add(networkGroup);

/* scan beam */
const beamGeo = new THREE.PlaneGeometry(0.06, 24);
const beamMat = new THREE.MeshBasicMaterial({ color:0xB08D57, transparent:true, opacity:0.5, side:THREE.DoubleSide });
const beam = new THREE.Mesh(beamGeo, beamMat);
beam.rotation.x = Math.PI/2;
beam.visible = false;
scene.add(beam);

const failNodeIndex = nodeFail.findIndex(f=>f);
const failNodeWorldPos = nodePos[failNodeIndex].clone();

/* ---- Moment 3: shard ---- */
const shardGeo = new THREE.PlaneGeometry(1.6, 1.0);
const shardMat = new THREE.MeshStandardMaterial({ color:0x17181C, roughness:0.4, metalness:0.2, side:THREE.DoubleSide, transparent:true, opacity:0 });
const shard = new THREE.Mesh(shardGeo, shardMat);
const shardEdges = new THREE.LineSegments(new THREE.EdgesGeometry(shardGeo), new THREE.LineBasicMaterial({ color:0x8C4A3A, transparent:true, opacity:0 }));
shard.add(shardEdges);
// shard mesh kept in memory for position math but not rendered — the DOM
// finding panel already conveys this moment, the 3D plane was redundant.

let shardDrag = { active:false, rx:0, ry:0 };

/* ---- Moment 4: crystal core ---- */
const coreGeo = new THREE.IcosahedronGeometry(1.1, 2);
const coreMat = new THREE.MeshPhysicalMaterial({
  color:0x1a2f5e, transmission:1, roughness:0.08, thickness:1.6, ior:1.4,
  transparent:true, opacity:0
});
const core = new THREE.Mesh(coreGeo, coreMat);
core.position.set(0,0,0);
scene.add(core);

const coreRingGroup = new THREE.Group();
coreRingGroup.position.set(0,0,0);
function makeRing(radius, tiltX, tiltZ, color){
  const geo = new THREE.TorusGeometry(radius, 0.028, 12, 96);
  const mat = new THREE.MeshBasicMaterial({ color, transparent:true, opacity:0 });
  const m = new THREE.Mesh(geo, mat);
  m.rotation.x = tiltX; m.rotation.z = tiltZ;
  coreRingGroup.add(m);
  return m;
}
const coreRing1 = makeRing(1.6, Math.PI/2.2, 0.3, 0xF2C879);
const coreRing2 = makeRing(2.0, Math.PI/2.8, -0.6, 0xDCE3E8);
const coreRing3 = makeRing(2.35, Math.PI/1.9, 1.1, 0xF7A94A);
scene.add(coreRingGroup);

/* ---- Moment 5: report plane + seal ---- */
const reportGeo = new THREE.BoxGeometry(2.0, 1.3, 0.03);
const reportMat = new THREE.MeshStandardMaterial({ color:0x101114, roughness:0.5, metalness:0.1, transparent:true, opacity:0 });
const report = new THREE.Mesh(reportGeo, reportMat);
report.position.set(0,0,0);
const reportEdges = new THREE.LineSegments(new THREE.EdgesGeometry(reportGeo), new THREE.LineBasicMaterial({ color:0x6E8574, transparent:true, opacity:0 }));
report.add(reportEdges);
scene.add(report);
const sealGeo = new THREE.TorusGeometry(0.16, 0.035, 12, 32);
const sealMat = new THREE.MeshStandardMaterial({ color:0x6E8574, emissive:0x1c2822, roughness:0.3, transparent:true, opacity:0 });
const seal = new THREE.Mesh(sealGeo, sealMat);
seal.position.set(0,0,0.03);
scene.add(seal);


/* Moment 6 ("one repository or a thousand") now reuses the same persistent
   star network below rather than a separate cluster of dots — camera just
   pulls back further to see more of it. */


camera.position.set(0,0,7);

/* ============ scroll progress ============ */
let progress = 0, displayProgress = 0;
function calcProgress(){
  const max = document.body.scrollHeight - innerHeight;
  progress = Math.min(1, Math.max(0, scrollY / max));
}
window.addEventListener('scroll', calcProgress, { passive:true });
calcProgress();

/* 7 moments, each 1/7 of progress */
const seg = 1/7;
function seg_t(i){ return Math.min(1, Math.max(0, (displayProgress - i*seg)/seg)); }

const lines = ['l0','l1','l2','l3','l4','l5'].map(id=>document.getElementById(id));
const skipEl = document.getElementById('skip');
const findingEl = document.getElementById('finding');
const hashEl = document.getElementById('hash');
const sub3 = document.getElementById('sub3');
const closeEl = document.getElementById('close');
const progFill = document.getElementById('progFill');
const progPct = document.getElementById('progPct');

function setLine(idx, on){ lines[idx] && lines[idx].classList.toggle('on', on); }

function lerp(a,b,t){ return a+(b-a)*t; }
function lerpV(v, target, t){ v.x=lerp(v.x,target.x,t); v.y=lerp(v.y,target.y,t); v.z=lerp(v.z,target.z,t); }

const camPath = [
  {p:new THREE.Vector3(0,0,7),  l:new THREE.Vector3(0,0,0)},   // 0 open
  {p:new THREE.Vector3(-2.5,1.2,8.5), l:new THREE.Vector3(0,0,0)}, // 1 scan
  {p:failNodeWorldPos.clone().multiplyScalar(0.35).add(new THREE.Vector3(1.2,0.6,1.4)), l:failNodeWorldPos}, // 2 shard zoom
  {p:new THREE.Vector3(-0.8,0.5,4.2), l:new THREE.Vector3(0,0,0)}, // 3 core
  {p:new THREE.Vector3(0.9,-0.3,3.6), l:new THREE.Vector3(0,0,0)}, // 4 report
  {p:new THREE.Vector3(3.5,3.5,16), l:new THREE.Vector3(0,0,-8)},    // 5 fleet
  {p:new THREE.Vector3(0,0,6),  l:new THREE.Vector3(0,0,0)},     // 6 close
];
const camLookTarget = new THREE.Vector3();
let prevCamX = 0, bankAngle = 0;

function updateScene(){
  const idx = Math.min(6, Math.floor(displayProgress/seg));
  const t = seg_t(idx);

  // camera lerp between waypoint idx and idx+1
  const from = camPath[idx], to = camPath[Math.min(6, idx+1)];
  lerpV(camera.position, new THREE.Vector3().lerpVectors(from.p, to.p, t), REDUCE?1:0.22);
  camLookTarget.lerpVectors(from.l, to.l, t);
  camera.lookAt(camLookTarget);

  // drone feel: continuous bank from lateral motion + a steady hover bob, always active
  const time = performance.now()*0.0002;
  const dx = camera.position.x - prevCamX;
  prevCamX = camera.position.x;
  bankAngle = lerp(bankAngle, -dx*2.2, 0.15);
  camera.rotation.z = bankAngle + Math.sin(time*2.3)*0.008;
  camera.position.y += Math.sin(time*1.7)*0.03;

  // idle drift
  // (bulk rotation removed — with the field this wide, spinning it swung stars
  // in and out of frame; cursor parallax + twinkle already carry the motion)
  stars.rotation.y = time*0.05;
  starMat.opacity = 0.4 + Math.sin(time*3)*0.1;
  // secondary idle tilt removed along with the bulk spin, same reasoning

  // ---- Moment 1 (idx0): idle network, dim color ----
  setLine(0, idx===0 && t<0.97);
  skipEl.style.opacity = displayProgress > 0.02 ? 0 : 1;

  // ---- Moment 2 (idx1): scan sweep ----
  const inScan = idx===1;
  setLine(1, inScan && t>0.02 && t<0.98);
  beam.visible = inScan;
  if(inScan){
    const beamX = lerp(-24, 24, t);
    beam.position.x = beamX;
    for(let i=0;i<N;i++){
      const passed = nodePos[i].x < beamX;
      setNodeState(i, !passed ? 'dim' : (nodeFail[i] ? 'fail' : 'safe'));
    }
  } else if(idx>1){
    for(let i=0;i<N;i++) setNodeState(i, nodeFail[i] ? 'fail' : 'safe');
  }
  // twinkle + occasional bright flash on every lit sprite, always running
  for(let i=0;i<N;i++){
    const s = nodeSprites[i].userData;
    s.color = s.color || DIM.clone();
    s.color.lerp(s.target, 0.08);
    s.op = lerp(s.op===undefined?0.35:s.op, s.targetOp, 0.08);
    if(Math.random() < 0.012) s.flash = 1.4;
    s.flash *= 0.86;
    const twinkle = 0.75 + Math.sin(time*260 + s.phase*60)*0.35;
    nodeSprites[i].material.color.copy(s.color);
    nodeSprites[i].material.opacity = Math.min(1.4, s.op*twinkle + s.flash);
    nodeSprites[i].scale.setScalar(s.base*(1+s.flash*2.2) * (0.88+twinkle*0.18));
  }

  // ---- Moment 3 (idx2): shard zoom ----
  const inShard = idx===2;
  setLine(2, inShard && t>0.02 && t<0.97);
  findingEl.classList.toggle('on', inShard && t>0.3);
  const shardOp = inShard ? Math.min(1, (t-0.1)*2) : (idx>2?1:0);
  shardMat.opacity = idx>=2 ? shardOp*0.9 : 0;
  shardEdges.material.opacity = idx>=2 ? shardOp : 0;
  if(idx<=2) shard.position.copy(failNodeWorldPos);
  // networkGroup stays visible for the whole scroll now — it's the persistent background
  if(!shardDrag.active){ shard.rotation.y += 0.003; }
  shard.rotation.x = shardDrag.rx; shard.rotation.y += shardDrag.ry*0; // base spin + drag offset applied via listeners

  // ---- Moment 4 (idx3): crystal core ----
  const inCore = idx===3;
  setLine(3, inCore && t>0.02 && t<0.97);
  sub3.classList.toggle('on', inCore && t>0.4);
  const coreOp = idx>=3 ? Math.min(1, idx===3 ? t*1.4 : 1) : 0;
  coreMat.opacity = coreOp;
  // staggered wave unfurl: each ring starts flattened (scaleY~0) and pops
  // open in sequence like a ripple sweeping across, instead of a flat fade
  const wave = (delay)=>{
    const wt = Math.min(1, Math.max(0, (t - delay) * 2.6));
    return Math.sin(wt * Math.PI * 0.5) + (wt>0 && wt<1 ? Math.sin(wt*Math.PI)*0.25 : 0);
  };
  const w1 = wave(0), w2 = wave(0.14), w3 = wave(0.28);
  coreRing1.scale.set(1, Math.max(0.04,w1), 1);
  coreRing2.scale.set(1, Math.max(0.04,w2), 1);
  coreRing3.scale.set(1, Math.max(0.04,w3), 1);
  coreRing1.material.opacity = coreOp*0.7*Math.min(1,w1+0.3);
  coreRing2.material.opacity = coreOp*0.7*Math.min(1,w2+0.3);
  coreRing3.material.opacity = coreOp*0.5*Math.min(1,w3+0.3);
  core.rotation.y += 0.004; core.rotation.x += 0.002;
  coreRingGroup.rotation.y -= 0.014; coreRingGroup.rotation.x += 0.007;
  shard.visible = idx <= 3;
  if(idx===3){
    shard.position.lerpVectors(failNodeWorldPos, core.position, Math.min(1, t*1.3));
    shard.scale.setScalar(lerp(1, 0.15, t));
    shardMat.opacity = lerp(0.9, 0, t);
    shardEdges.material.opacity = lerp(1,0,t);
  }

  // ---- Moment 5 (idx4): report + seal ----
  const inReport = idx===4;
  setLine(4, inReport && t>0.02 && t<0.97);
  const repOp = idx>=4 ? Math.min(1, (idx===4? t*1.6:1)) : 0;
  reportMat.opacity = repOp*0.95; reportEdges.material.opacity = repOp;
  const sealT = idx===4 ? Math.min(1, Math.max(0,(t-0.35)*2.4)) : (idx>4?1:0);
  seal.scale.setScalar(0.6 + sealT*0.4 + (sealT>0 && sealT<1 ? Math.sin(sealT*Math.PI)*0.15 : 0));
  sealMat.opacity = sealT;
  hashEl.classList.toggle('on', inReport && t>0.55);
  core.visible = idx >= 3 && idx <= 4;
  coreRingGroup.visible = true;
  if(idx===4){
    coreRing1.scale.set(1,1,1); coreRing2.scale.set(1,1,1); coreRing3.scale.set(1,1,1);
    const k = lerp(1,0.35,Math.min(1,t*1.2)); // settle to a faint ambient level, not zero
    coreMat.opacity = k * (1 - Math.min(1,t*1.2)); // core mesh itself still fully fades
    coreRing1.material.opacity = k*0.7; coreRing2.material.opacity = k*0.7; coreRing3.material.opacity = k*0.5;
  } else if(idx>4){
    coreRing1.material.opacity = 0.35*0.7; coreRing2.material.opacity = 0.35*0.7; coreRing3.material.opacity = 0.35*0.5;
  }

  // ---- Moment 6 (idx5): fleet pull back ----
  const inFleet = idx===5;
  setLine(5, inFleet && t>0.02 && t<0.97);
  // (fleet visibility removed — main star network is always on)
  report.visible = idx <= 4;
  seal.visible = idx <= 4;
  // report/seal now hide immediately at the end of their own moment (above),

  // ---- Moment 7 (idx6): close ----
  closeEl.classList.toggle('on', idx===6 && t>0.2);
  if(idx===6){ scene.fog.density = lerp(0.035, 0.12, t); }

  progFill.style.height = (displayProgress*100)+'%';
  progPct.textContent = String(Math.round(displayProgress*100)).padStart(2,'0')+'%';
}

/* shard drag interaction (only meaningful in moment 3) */
let dragging=false, lastX=0, lastY=0;
renderer.domElement.addEventListener('pointerdown', e=>{
  const idx = Math.floor(displayProgress/seg);
  if(idx!==2) return;
  dragging=true; lastX=e.clientX; lastY=e.clientY;
});
window.addEventListener('pointermove', e=>{
  if(!dragging) return;
  const dx=e.clientX-lastX, dy=e.clientY-lastY;
  shard.rotation.y += dx*0.006;
  shard.rotation.x += dy*0.006;
  lastX=e.clientX; lastY=e.clientY;
});
window.addEventListener('pointerup', ()=> dragging=false);

/* cursor parallax on network */
window.addEventListener('mousemove', e=>{
  const nx = (e.clientX/innerWidth)-0.5, ny=(e.clientY/innerHeight)-0.5;
  networkGroup.rotation.z = -nx*0.06;
  key.position.x = 6 + nx*3; key.position.y = 8 - ny*3;
});

/* ============ resize ============ */
window.addEventListener('resize', ()=>{
  camera.aspect = innerWidth/innerHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(innerWidth, innerHeight);
  calcProgress();
});

/* ============ render loop ============ */
function animate(){
  requestAnimationFrame(animate);
  displayProgress = lerp(displayProgress, progress, REDUCE?1:0.18);
  updateScene();
  renderer.render(scene, camera);
}
animate();

window.addEventListener('load', ()=>{
  setTimeout(()=>{
    const l = document.getElementById('loader');
    l.style.opacity = 0;
    setTimeout(()=> l.style.display='none', 650);
  }, 300);
});
