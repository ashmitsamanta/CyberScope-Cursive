# CYBERSCOPE — 3-Minute Live Hackathon Demo Script

## Target Audience
Hackathon Judges, Cybersecurity Evaluators, and SOC / Fraud Operations Teams.

---

## Step 1: Establish Context & Dashboard (30 Seconds)
1. Open the browser to **`http://localhost:5173`**.
2. **Key Talking Point:**
   > "Welcome to CYBERSCOPE. Fraud does not happen in silos; it moves across coordinated evidence chains. In traditional systems, each alert is handled independently. In CYBERSCOPE, 42 synthetic incoming incident files are immediately analyzed for behavioral anomalies, shared infrastructure, and money movement."
3. Highlight the top KPIs: **42 Cases**, **7 High Risk**, **2 Critical**, **3 Detected Campaigns**, and the active **Campaign Overview** cards.

---

## Step 2: Open an Apparently Isolated Case
1. Click on case **`CS-1024`** (*"Simulated KYC Suspension Alert - Victim Rajiv"*).
2. This immediately loads the flagship **Investigation Workspace**.

---

## Step 3: Explain the Risk Breakdown & Arithmetic
1. Direct attention to the **Investigation Risk Score** badge: **`84/100 (HIGH)`**.
2. **Key Talking Point:**
   > "Notice this score is not a black-box percentage. Looking at the right panel, every single point is mathematically accounted for and sums exactly to 84:
   > - **+20 PTS**: Known Suspicious Identifier (`+919686579303`, Risk: 85/100)
   > - **+15 PTS**: Shared Campaign Infrastructure (appears across 5 incidents)
   > - **+15 PTS**: Multi-Case Syndicate Association
   > - **+15 PTS**: Suspicious Communication Urgency & Impersonation
   > - **+15 PTS**: Rapid Fund Dispersion (routing to secondary mules within minutes)
   > - **+4 PTS**: Elevated Exposure Amount (₹48,500)
   > Total: 84 / 100, placing it squarely in the HIGH severity threshold (70–89), below the CRITICAL threshold (90–100)."
3. Toggle the **Timeline** tab to show the chronological sequence from the initial SMS to the ₹48,500 transfer.

---

## Step 4: Expand the Fraud Graph ("Find Connections")
1. Click the **"Find Connections"** button in the header (or above the graph).
2. **Key Talking Point:**
   > "Watch what happens when the investigator clicks 'Find Connections'. The graph expands from 1 hop to 2 hops. Suddenly, this isolated victim is connected to a phishing domain: `secure-kyc-update.com`."
3. Click **"Find Connections"** again (3-Hops).
4. **Key Talking Point:**
   > "Expanding one more hop reveals the full syndicate: cases CS-1025 and CS-1026, telephone senders, and the central collection UPI ID `centralmule99@okaxis`."

---

## Step 5: Trace the Money Flow
1. Scroll down to the bottom left **"Simulated Money-Flow Trace"** panel.
2. Click **"Trace Funds"**.
3. **Key Talking Point:**
   > "Here is our graph traversal engine in action. Victim Rajiv transferred ₹48,500 to the Primary Mule Hub. Within 4 minutes, the hub executed a Fan-Out split across three secondary accounts, and forwarded onward to an exit node. Layering and Fan-out anomalies are flagged automatically."

---

## Step 6: Inquire with CYBER-ASSIST (Grounded AI Investigator)
1. Turn to the bottom right **CYBER-ASSIST** terminal.
2. Click the quick prompt: **`Why was this case flagged?`**
   - The AI returns an evidence-grounded response citing `[CS-1024]`, `[DOMAIN-1]`, and itemizing observed signals.
3. Click the prompt: **`What entities connect these cases?`**
   - The AI identifies the shared domain and collection UPI handle.
4. Click: **`What should an investigator examine next?`**
   - The AI delivers concrete, strategic defensive steps (account freezing, registrar takedowns, payment gateway velocity limits).

---

## Step 7: Conclusion
1. **Closing Statement:**
   > "In less than 3 minutes, CYBERSCOPE transformed an isolated victim SMS into an uncovered multi-case syndicate, fully traced the money movement, and provided structured, evidence-grounded findings ready for defensive action."
