# 🚀 คู่มือ Deploy OSIRIS บน Netlify (ภาษาไทย)

OSIRIS เป็นแพลตฟอร์ม **OSINT / ข่าวกรองโอเพนซอร์ส** สร้างด้วย Next.js 16 + MapLibre GL
เวอร์ชันนี้ **แปลเมนูเป็นภาษาไทย** และ **ปรับแต่งให้ deploy บน Netlify ได้ทันที**

---

## ✅ สิ่งที่ปรับแต่งไว้ให้แล้ว

| รายการ | รายละเอียด |
|--------|-----------|
| เมนูภาษาไทย | เมนูเลเยอร์, แท็บ RECON, HUD, คีย์ลัด, metadata (`lang="th"`) |
| `netlify.toml` | ตั้งค่า build + ปลั๊กอิน `@netlify/plugin-nextjs` (OpenNext) |
| `next.config.ts` | เอา `output: 'standalone'` ออก (โหมดนั้นสำหรับ Docker) |
| ลบ middleware | เอา analytics ที่ยิงไป Docker host ภายในออก (เสี่ยง Edge Function ล้มเหลว) |
| ไม่ต้องใช้ API key | ฟีดหลักทุกตัวใช้แหล่งสาธารณะ ใช้งานได้ทันที |

> รองรับ **Next.js 16.2.6** ซึ่งเป็นเวอร์ชันที่ Netlify รองรับโดยตรง — Netlify จะติดตั้ง Next.js Runtime ให้อัตโนมัติตอน build

---

## วิธีที่ 1 — Deploy ผ่าน Git (แนะนำ)

1. **อัปขึ้น GitHub / GitLab**
   ```bash
   cd osiris-master
   git init
   git add .
   git commit -m "OSIRIS เมนูไทย พร้อม deploy Netlify"
   git branch -M main
   git remote add origin https://github.com/<ชื่อคุณ>/osiris.git
   git push -u origin main
   ```

2. **เชื่อมกับ Netlify**
   - เข้า https://app.netlify.com → **Add new site → Import an existing project**
   - เลือก repo ที่เพิ่ง push
   - Netlify จะตรวจเจอ Next.js เองและอ่านค่าจาก `netlify.toml`:
     - Build command: `npm run build`
     - Publish directory: `.next`
   - กด **Deploy site** — เสร็จแล้วจะได้ลิงก์ `https://<ชื่อ>.netlify.app`

3. **(ไม่บังคับ) ใส่ Environment Variables**
   ไปที่ **Site settings → Environment variables** แล้วเพิ่มค่าตาม `.env.template`
   เฉพาะเมื่อต้องการเปิด RECON Scanner หรือเพิ่ม rate limit

---

## วิธีที่ 2 — Deploy ผ่าน Netlify CLI

```bash
npm install -g netlify-cli
cd osiris-master
npm install

# ทดสอบในเครื่องก่อน (จำลองสภาพแวดล้อม Netlify)
netlify dev

# deploy production
netlify deploy --build --prod
```

> หมายเหตุ: หาก deploy ด้วย CLI ในเครื่อง **ต้องใช้ `netlify deploy --build`**
> เพราะปลั๊กอินจะสร้างไฟล์ที่จำเป็นตอน build ให้

---

## 🖥️ รันในเครื่อง (Local Development)

```bash
cd osiris-master
npm install
npm run dev          # เปิด http://localhost:3000

# หรือทดสอบเวอร์ชัน production
npm run build
npm start
```

---

## 🧩 เมนูภาษาไทยที่แปลแล้ว

**เลเยอร์แผนที่:** การบิน · ทางทะเล · การสอดส่อง · ภัยพิบัติ · ภัยคุกคาม · เครือข่าย · การแสดงผล
(พาณิชย์ / ส่วนตัว / ทหาร / ดาวเทียม / กล้อง CCTV / แผ่นดินไหว / ไฟกำลังลุก ฯลฯ)

**ชุดเครื่องมือสำรวจ (RECON):** สแกนพอร์ต · สแกนช่องโหว่ · DNS · WHOIS · ใบรับรอง · ภัยคุกคาม ·
เฮดเดอร์ · SSL/TLS · ซับโดเมน · ตรวจเทคโนโลยี · SHODAN IoT · เส้นทาง BGP · MAC แอดเดรส ·
ข่าวกรองเบอร์โทร · ข้อมูลรั่วไหล · สำรวจ GitHub · สแกน IP

---

## ⚠️ ข้อควรทราบ

- **RECON Scanner (สแกนพอร์ต/ช่องโหว่)** ต้องมี backend แยก (`SCANNER_URL` + `SCANNER_KEY`)
  ถ้าไม่ตั้งจะคืน 503 — ฟีเจอร์อื่นทำงานปกติ
- Netlify **ไม่รองรับการเขียนไฟล์ลง filesystem** — โปรเจกต์นี้ตรวจแล้วว่าไม่มี API ที่เขียนไฟล์
- ใช้เครื่องมือ OSINT อย่างถูกกฎหมายและมีจริยธรรม สแกนเฉพาะระบบที่ได้รับอนุญาตเท่านั้น

---

*ระบบเดิม OSIRIS โดย simplifaisoul (MIT License) — เวอร์ชันนี้แปลเมนูไทยและปรับสำหรับ Netlify*
