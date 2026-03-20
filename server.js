
const express=require("express");
const sqlite3=require("sqlite3").verbose();
const bcrypt=require("bcryptjs");
const session=require("express-session");
const multer=require("multer");
const path=require("path");
const fs=require("fs");
const helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const PDFDocument=require("pdfkit");

const app=express();
app.use(helmet({ contentSecurityPolicy:false, crossOriginEmbedderPolicy:false }));
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname,"public")));
app.use("/uploads",express.static(path.join(__dirname,"uploads")));
app.use(session({
  secret:process.env.SESSION_SECRET||"massfix_secret_change_me",
  resave:false,
  saveUninitialized:false,
  cookie:{maxAge:1000*60*60*12,httpOnly:true,sameSite:"lax"}
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Muitas tentativas. Aguarde e tente novamente."
});

const storage=multer.diskStorage({
  destination:(req,file,cb)=>cb(null,path.join(__dirname,"uploads")),
  filename:(req,file,cb)=>{
    const safe=(file.originalname||"arquivo.jpg").replace(/\s+/g,"_").replace(/[^a-zA-Z0-9._-]/g,"");
    cb(null,Date.now()+"_"+safe);
  }
});
const upload=multer({
  storage,
  limits:{fileSize:10*1024*1024},
  fileFilter:(req,file,cb)=>{
    if((file.mimetype||"").startsWith("image/")) return cb(null,true);
    cb(new Error("Apenas imagens sao permitidas."));
  }
});

const db=new sqlite3.Database(path.join(__dirname,"database.db"));

db.serialize(()=>{
  db.run(`CREATE TABLE IF NOT EXISTS motoristas(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    cpf TEXT NOT NULL UNIQUE,
    placa TEXT NOT NULL,
    senha TEXT NOT NULL,
    foto_perfil TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS administradores(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT NOT NULL UNIQUE,
    senha TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS configuracoes(
    chave TEXT PRIMARY KEY,
    valor TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS registros(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cpf TEXT NOT NULL,
    nome TEXT NOT NULL,
    placa TEXT NOT NULL,
    tipo TEXT NOT NULL,
    valor REAL NOT NULL,
    ordem TEXT NOT NULL,
    caixa TEXT NOT NULL,
    latitude TEXT,
    longitude TEXT,
    foto_nf TEXT,
    foto_recebimento TEXT,
    foto_despesa TEXT,
    descricao_despesa TEXT,
    observacao TEXT,
    origem TEXT DEFAULT 'app',
    status_pagamento TEXT DEFAULT 'pendente',
    pago_em DATETIME,
    comprovante_pagamento TEXT,
    data DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`INSERT OR IGNORE INTO configuracoes(chave, valor) VALUES
    ('nome_empresa','Massfix Reciclagem de Vidros'),
    ('logo_site',''),
    ('imagem_home',''),
    ('valor_almoco','35'),
    ('valor_janta','35'),
    ('valor_pernoite','200'),
    ('link_download_app','/login.html')
  `);

  db.get("SELECT COUNT(*) AS total FROM administradores", [], async (err,row)=>{
    if(!err && row && row.total===0){
      const hash=await bcrypt.hash("admin123",10);
      db.run("INSERT INTO administradores(usuario,senha) VALUES(?,?)",["admin",hash]);
    }
  });

  db.all("PRAGMA table_info(motoristas)", [], (err, rows) => {
    if (err || !rows) return;
    const cols = rows.map(r => r.name);
    if (!cols.includes("foto_perfil")) db.run("ALTER TABLE motoristas ADD COLUMN foto_perfil TEXT");
  });
});

const normalizeCPF=v=>String(v||"").replace(/\D/g,"");
const normalizePlate=v=>String(v||"").trim().toUpperCase();

const requireAuth=(req,res,next)=>!req.session.user?res.status(401).send("Faca login primeiro."):next();
const requireAdmin=(req,res,next)=>!req.session.admin?res.status(401).send("Faca login como administrador."):next();

function uploadFields(req,res,next){
  upload.fields([
    {name:"foto_nf",maxCount:1},
    {name:"foto_recebimento",maxCount:1},
    {name:"foto_despesa",maxCount:1},
    {name:"foto_perfil",maxCount:1},
    {name:"logo_site",maxCount:1},
    {name:"imagem_home",maxCount:1}
  ])(req,res,err=>err?res.status(400).send(err.message||"Erro no upload."):next());
}

function moeda(v){ return Number(v||0).toFixed(2); }

app.get("/config", (req,res)=>{
  db.all("SELECT chave, valor FROM configuracoes", [], (err, rows)=>{
    if(err) return res.status(500).json({});
    const obj={};
    (rows||[]).forEach(r=>obj[r.chave]=r.valor);
    res.json(obj);
  });
});

app.post("/cadastro", loginLimiter, async (req,res)=>{
  const nome=String(req.body.nome||"").trim();
  const cpf=normalizeCPF(req.body.cpf);
  const placa=normalizePlate(req.body.placa);
  const senha=String(req.body.senha||"");
  if(!nome||!cpf||!placa||!senha) return res.status(400).send("Preencha todos os campos.");
  if(cpf.length!==11) return res.status(400).send("CPF invalido.");
  if(senha.length < 4) return res.status(400).send("A senha deve ter no minimo 4 caracteres.");
  const hash=await bcrypt.hash(senha,10);
  db.run("INSERT INTO motoristas(nome,cpf,placa,senha) VALUES(?,?,?,?)",[nome,cpf,placa,hash],err=>err?res.status(400).send("CPF ja cadastrado."):res.send("ok"));
});

app.post("/login", loginLimiter, (req,res)=>{
  const cpf=normalizeCPF(req.body.cpf);
  const senha=String(req.body.senha||"");
  db.get("SELECT * FROM motoristas WHERE cpf=?",[cpf],async(err,user)=>{
    if(err) return res.status(500).send("Erro no servidor.");
    if(!user) return res.status(401).send("CPF nao encontrado.");
    const ok=await bcrypt.compare(senha,user.senha);
    if(!ok) return res.status(401).send("Senha invalida.");
    req.session.user={id:user.id,nome:user.nome,cpf:user.cpf,placa:user.placa,foto_perfil:user.foto_perfil||""};
    res.send("ok");
  });
});

app.post("/admin/login", loginLimiter, (req,res)=>{
  const usuario=String(req.body.usuario||"").trim();
  const senha=String(req.body.senha||"");
  db.get("SELECT * FROM administradores WHERE usuario=?",[usuario],async(err,admin)=>{
    if(err) return res.status(500).send("Erro no servidor.");
    if(!admin) return res.status(401).send("Usuario nao encontrado.");
    const ok=await bcrypt.compare(senha,admin.senha);
    if(!ok) return res.status(401).send("Senha invalida.");
    req.session.admin={id:admin.id,usuario:admin.usuario};
    res.send("ok");
  });
});

app.post("/admin/alterar-senha", requireAdmin, async (req,res)=>{
  const senhaAtual = String(req.body.senha_atual || "");
  const novaSenha = String(req.body.nova_senha || "");
  if(!senhaAtual || !novaSenha) return res.status(400).send("Informe a senha atual e a nova senha.");
  if(novaSenha.length < 6) return res.status(400).send("A nova senha deve ter no minimo 6 caracteres.");
  db.get("SELECT * FROM administradores WHERE id=?", [req.session.admin.id], async (err, admin)=>{
    if(err || !admin) return res.status(404).send("Administrador nao encontrado.");
    const ok = await bcrypt.compare(senhaAtual, admin.senha);
    if(!ok) return res.status(401).send("Senha atual incorreta.");
    const hash = await bcrypt.hash(novaSenha, 10);
    db.run("UPDATE administradores SET senha=? WHERE id=?", [hash, admin.id], err2=>err2?res.status(500).send("Erro ao atualizar senha."):res.send("ok"));
  });
});

app.post("/logout",(req,res)=>req.session.destroy(()=>res.send("ok")));
app.get("/me",requireAuth,(req,res)=>res.json(req.session.user));
app.get("/admin/me",requireAdmin,(req,res)=>res.json(req.session.admin));

app.post("/registro",requireAuth,uploadFields,(req,res)=>{
  const u=req.session.user;
  const tipo=String(req.body.tipo||"").trim();
  const valor=Number(req.body.valor||0);
  const ordem=String(req.body.ordem||"").trim();
  const caixa=String(req.body.caixa||"").trim();
  const latitude=String(req.body.latitude||"").trim();
  const longitude=String(req.body.longitude||"").trim();
  const observacao=String(req.body.observacao||"").trim();
  const origem=String(req.body.origem||"app").trim();
  const descricao_despesa=String(req.body.descricao_despesa||"").trim();
  if(!tipo||!valor||!ordem||!caixa) return res.status(400).send("Preencha ordem e caixa.");
  if(tipo==="outras_despesas"&&!descricao_despesa) return res.status(400).send("Descreva a despesa adicional.");

  const files=req.files||{};
  const foto_nf=files.foto_nf?.[0]?.filename||null;
  const foto_recebimento=files.foto_recebimento?.[0]?.filename||null;
  const foto_despesa=files.foto_despesa?.[0]?.filename||null;

  db.run(`INSERT INTO registros(cpf,nome,placa,tipo,valor,ordem,caixa,latitude,longitude,foto_nf,foto_recebimento,foto_despesa,descricao_despesa,observacao,origem)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [u.cpf,u.nome,u.placa,tipo,valor,ordem,caixa,latitude,longitude,foto_nf,foto_recebimento,foto_despesa,descricao_despesa,observacao,origem],
    err=>err?res.status(500).send("Erro ao salvar o registro."):res.send("ok"));
});

app.get("/me/pagamentos",requireAuth,(req,res)=>{
  db.all("SELECT id,tipo,valor,ordem,caixa,status_pagamento,pago_em,comprovante_pagamento,data FROM registros WHERE cpf=? ORDER BY datetime(data) DESC,id DESC",
    [req.session.user.cpf],(err,rows)=>err?res.status(500).json([]):res.json(rows||[]));
});

app.get("/admin/dados",requireAdmin,(req,res)=>{
  db.all("SELECT * FROM registros ORDER BY datetime(data) DESC,id DESC",[],(err,rows)=>err?res.status(500).json([]):res.json(rows||[]));
});

app.get("/admin/motoristas", requireAdmin, (req,res)=>{
  db.all("SELECT * FROM motoristas ORDER BY nome ASC", [], (err, rows)=>err?res.status(500).json([]):res.json(rows||[]));
});

app.post("/admin/motoristas/:id", requireAdmin, uploadFields, (req,res)=>{
  const id=Number(req.params.id||0);
  const nome=String(req.body.nome||"").trim();
  const placa=normalizePlate(req.body.placa);
  const files=req.files||{};
  const foto_perfil=files.foto_perfil?.[0]?.filename||null;

  db.get("SELECT * FROM motoristas WHERE id=?", [id], (err, row)=>{
    if(err || !row) return res.status(404).send("Motorista nao encontrado.");
    const novoNome = nome || row.nome;
    const novaPlaca = placa || row.placa;
    const novaFoto = foto_perfil || row.foto_perfil || "";
    db.run("UPDATE motoristas SET nome=?, placa=?, foto_perfil=? WHERE id=?",
      [novoNome, novaPlaca, novaFoto, id],
      err2=>{
        if(err2) return res.status(500).send("Erro ao atualizar motorista.");
        db.run("UPDATE registros SET nome=?, placa=? WHERE cpf=?", [novoNome, novaPlaca, row.cpf]);
        res.send("ok");
      });
  });
});

app.post("/admin/config", requireAdmin, uploadFields, (req,res)=>{
  const files=req.files||{};
  const updates = [];
  const simpleFields = ["nome_empresa","valor_almoco","valor_janta","valor_pernoite","link_download_app"];
  simpleFields.forEach(k=>{
    const v = String(req.body[k] || "").trim();
    if(v) updates.push([k,v]);
  });
  const logo = files.logo_site?.[0]?.filename || null;
  const home = files.imagem_home?.[0]?.filename || null;
  if(logo) updates.push(["logo_site", logo]);
  if(home) updates.push(["imagem_home", home]);
  if(!updates.length) return res.status(400).send("Nada para atualizar.");

  let pending = updates.length;
  let failed = false;
  updates.forEach(([chave, valor])=>{
    db.run("INSERT INTO configuracoes(chave, valor) VALUES(?, ?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor",
      [chave, valor],
      err=>{
        if(failed) return;
        if(err){ failed = true; return res.status(500).send("Erro ao salvar configuracoes."); }
        pending--;
        if(pending===0) res.send("ok");
      });
  });
});

app.get("/admin/relatorio-mensal", requireAdmin, (req,res)=>{
  const mes = String(req.query.mes || "").trim();
  if(!mes) return res.status(400).json([]);
  db.all(`
    SELECT nome, cpf, placa,
      SUM(CASE WHEN tipo='almoco' THEN valor ELSE 0 END) AS almoco_total,
      SUM(CASE WHEN tipo='janta' THEN valor ELSE 0 END) AS janta_total,
      SUM(CASE WHEN tipo='pernoite' THEN valor ELSE 0 END) AS pernoite_total,
      SUM(CASE WHEN tipo='outras_despesas' THEN valor ELSE 0 END) AS outras_total,
      SUM(valor) AS total_geral
    FROM registros
    WHERE strftime('%Y-%m', data)=?
    GROUP BY nome, cpf, placa
    ORDER BY total_geral DESC
  `,[mes],(err,rows)=>err?res.status(500).json([]):res.json(rows||[]));
});

app.get("/admin/relatorio-pdf", requireAdmin, (req,res)=>{
  const mes = String(req.query.mes || "").trim();
  if(!mes) return res.status(400).send("Informe o mes no formato YYYY-MM.");
  db.all(`
    SELECT nome, cpf, placa,
      SUM(CASE WHEN tipo='almoco' THEN valor ELSE 0 END) AS almoco_total,
      SUM(CASE WHEN tipo='janta' THEN valor ELSE 0 END) AS janta_total,
      SUM(CASE WHEN tipo='pernoite' THEN valor ELSE 0 END) AS pernoite_total,
      SUM(CASE WHEN tipo='outras_despesas' THEN valor ELSE 0 END) AS outras_total,
      SUM(valor) AS total_geral
    FROM registros
    WHERE strftime('%Y-%m', data)=?
    GROUP BY nome, cpf, placa
    ORDER BY total_geral DESC
  `,[mes],(err,rows)=>{
    if(err) return res.status(500).send("Erro ao gerar relatorio PDF.");
    const doc = new PDFDocument({ margin: 40, size: "A4" });
    res.setHeader("Content-Type","application/pdf");
    res.setHeader("Content-Disposition",`attachment; filename=relatorio-${mes}.pdf`);
    doc.pipe(res);

    doc.fontSize(20).text("Relatorio Mensal - Massfix", { align:"left" });
    doc.moveDown(0.3);
    doc.fontSize(11).fillColor("#555").text(`Mes: ${mes}`);
    doc.fillColor("black");
    doc.moveDown(1);

    let y = doc.y;
    const cols = [40, 180, 250, 320, 390, 470];
    doc.fontSize(10).font("Helvetica-Bold");
    ["Motorista","Almoco","Janta","Pernoite","Outras","Total"].forEach((h,i)=>doc.text(h, cols[i], y));
    y += 18;
    doc.moveTo(40,y).lineTo(555,y).strokeColor("#cccccc").stroke();
    y += 8;
    doc.font("Helvetica");

    rows.forEach(r=>{
      if(y > 740){ doc.addPage(); y = 40; }
      doc.text(String(r.nome||""), cols[0], y, { width: 130 });
      doc.text("R$ "+moeda(r.almoco_total), cols[1], y);
      doc.text("R$ "+moeda(r.janta_total), cols[2], y);
      doc.text("R$ "+moeda(r.pernoite_total), cols[3], y);
      doc.text("R$ "+moeda(r.outras_total), cols[4], y);
      doc.text("R$ "+moeda(r.total_geral), cols[5], y);
      y += 20;
    });

    doc.moveDown(1);
    const totalGeral = rows.reduce((acc,r)=>acc + Number(r.total_geral||0),0);
    doc.font("Helvetica-Bold").text("Total geral do mes: R$ " + moeda(totalGeral), 40, y+10);
    doc.end();
  });
});

app.post("/admin/registros/:id/pagar",requireAdmin,(req,res)=>{
  const id=Number(req.params.id||0);
  db.get("SELECT * FROM registros WHERE id=?",[id],(err,registro)=>{
    if(err||!registro) return res.status(404).send("Registro nao encontrado.");
    if(registro.status_pagamento==="pago") return res.status(400).send("Este registro ja foi pago.");
    const html=`<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><title>Comprovante</title></head><body style="font-family:Arial;padding:24px"><h1>Comprovante de Pagamento</h1><p><b>Motorista:</b> ${registro.nome}</p><p><b>CPF:</b> ${registro.cpf}</p><p><b>Placa:</b> ${registro.placa}</p><p><b>Tipo:</b> ${registro.tipo}</p><p><b>Valor:</b> R$ ${moeda(registro.valor)}</p><p><b>Ordem:</b> ${registro.ordem}</p><p><b>Caixa:</b> ${registro.caixa}</p><p><b>Pago em:</b> ${new Date().toLocaleString("pt-BR")}</p></body></html>`;
    const filename=`comprovante_pagamento_${registro.id}.html`;
    fs.writeFile(path.join(__dirname,"uploads",filename),html,"utf8",errFile=>{
      if(errFile) return res.status(500).send("Erro ao gerar comprovante.");
      db.run("UPDATE registros SET status_pagamento='pago', pago_em=CURRENT_TIMESTAMP, comprovante_pagamento=? WHERE id=?",
        [filename,id],err2=>err2?res.status(500).send("Erro ao marcar pagamento."):res.send("ok"));
    });
  });
});

const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log(`Massfix profissional rodando em http://localhost:${PORT}`));
