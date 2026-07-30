// NeuroSploit v3.5.1 — Typst report template (blank, structured).
//
// The harness generates `report.typ` per run by prepending a `findings` array
// and a `meta` dict, then including this template's rendering logic. This file
// is the reference/blank template: it renders a cover, an executive summary with
// severity counts, and one section per finding. Compile with:
//     typst compile report.typ report.pdf
//
// Expected inputs (defined above this template in the generated file):
//   #let meta = (target: "", run_id: "", generated: "", model: "")
//   #let findings = ( (severity: "", title: "", agent: "", cwe: "", cvss: "",
//                      endpoint: "", payload: "", evidence: "", impact: "",
//                      remediation: "", votes: "", confidence: 0.0), ... )

#let sevcolor = (
  Critical: rgb("#c0392b"), High: rgb("#e67e22"), Medium: rgb("#f1c40f"),
  Low: rgb("#3498db"), Info: rgb("#7f8c8d"),
)
#let sevbadge(s) = box(
  fill: sevcolor.at(s, default: rgb("#7f8c8d")), inset: (x: 5pt, y: 2pt),
  radius: 3pt, text(fill: white, weight: "bold", size: 8pt, upper(s)),
)
#let sevrank(s) = (Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4).at(s, default: 5)

#set page(margin: 2cm, numbering: "1", footer: context [
  #set text(size: 8pt, fill: gray)
  NeuroSploit v3.5.1 · #meta.target · confidential
  #h(1fr) #counter(page).display()
])
#set text(font: ("Helvetica Neue", "Helvetica", "Arial"), size: 10pt)
#set heading(numbering: none)

// ---- Cover ----
#v(3cm)
#align(center)[
  #text(28pt, weight: "bold")[#text(fill: rgb("#7c5cff"))[Neuro]Sploit]
  #v(2pt)
  #text(15pt, fill: gray)[Penetration Test Report]
  #v(1cm)
  #text(14pt)[Asset: #strong(meta.asset)]
  #v(4pt)
  #text(11pt, fill: gray)[#meta.target]
  #v(2pt)
  #if meta.tech != "" [ #text(9pt, fill: gray)[Stack: #meta.tech] #v(2pt) ]
  #v(6pt)
  #text(10pt, fill: gray)[Run #meta.run_id · #meta.generated · models: #meta.model]
  #v(8pt)
  #text(9pt, fill: gray)[by #strong[Joas A Santos] & #strong[Red Team Leaders]]
]
#pagebreak()

// ---- Asset under test ----
= Asset Under Test
#table(columns: (auto, 1fr), inset: 6pt, stroke: 0.5pt + rgb("#dddddd"), align: left + horizon,
  text(9pt, fill: gray)[Asset], text(9pt)[#strong(meta.asset)],
  text(9pt, fill: gray)[URL / target], text(9pt)[#raw(meta.target)],
  ..(if meta.tech != "" { (text(9pt, fill: gray)[Technology], text(9pt)[#meta.tech]) } else { () }),
  ..(if meta.server != "" { (text(9pt, fill: gray)[Server], text(9pt)[#meta.server]) } else { () }),
)
#v(8pt)

// ---- Executive summary ----
= Executive Summary
#text(10pt)[#meta.exec]

#let counts = (:)
#for f in findings {
  if f.status != "needs-review" { counts.insert(f.severity, counts.at(f.severity, default: 0) + 1) }
}
#if findings.len() == 0 [
] else [
  #v(6pt)
  #grid(columns: 5, gutter: 8pt,
    ..("Critical", "High", "Medium", "Low", "Info").map(s => box(
      width: 100%, inset: 8pt, radius: 6pt, stroke: 0.5pt + sevcolor.at(s),
      align(center)[
        #text(18pt, weight: "bold", fill: sevcolor.at(s))[#str(counts.at(s, default: 0))]
        #v(-4pt) #text(8pt, upper(s))
      ],
    ))
  )
]

#let sorted = findings.sorted(key: f => sevrank(f.severity))

// ---- Vulnerability summary table ----
#if sorted.len() > 0 [
  #v(8pt)
  == Vulnerability Summary
  #v(4pt)
  #table(
    columns: (auto, 1fr, auto, auto, auto),
    inset: 6pt, align: (left + horizon, left + horizon, center + horizon, center + horizon, center + horizon),
    stroke: 0.5pt + rgb("#dddddd"),
    table.header(
      text(weight: "bold")[\#], text(weight: "bold")[Vulnerability],
      text(weight: "bold")[Severity], text(weight: "bold")[Status], text(weight: "bold")[OWASP / CWE],
    ),
    ..sorted.enumerate().map(((i, f)) => (
      str(i + 1), f.title, sevbadge(f.severity),
      if f.status == "needs-review" { text(8pt, fill: rgb("#8e44ad"))[needs-review] } else { text(8pt, fill: rgb("#27ae60"))[confirmed] },
      f.owasp,
    )).flatten()
  )
]

// ---- Test accounts created ----
#if meta.accounts != "" [
  #v(8pt)
  == Test Accounts Created (delete after)
  #v(3pt)
  #text(9pt, fill: gray)[Created to reach the authenticated surface. Credentials are in the run vault (.neurosploit/vault/<run-id>.json); delete once testing is complete.]
  #v(3pt)
  #block(width: 100%, inset: 8pt, radius: 4pt, fill: rgb("#faf7ff"), text(9pt)[#meta.accounts])
]

#v(10pt)
#line(length: 100%, stroke: 0.5pt + gray)

// ---- Detailed findings ----
= Findings
#if sorted.len() == 0 [
  #text(fill: gray)[_Nothing to report._]
]
#for (i, f) in sorted.enumerate() [
  #block(breakable: false, width: 100%, inset: 10pt, radius: 6pt,
    stroke: (left: 3pt + sevcolor.at(f.severity, default: gray), rest: 0.5pt + rgb("#dddddd")))[
    #sevbadge(f.severity) #h(6pt)
    #if f.status == "needs-review" [ #box(fill: rgb("#8e44ad"), inset: (x: 5pt, y: 2pt), radius: 3pt, text(fill: white, weight: "bold", size: 8pt)[NEEDS REVIEW]) #h(6pt) ]
    #text(12pt, weight: "bold")[#str(i + 1). #f.title]
    #v(4pt)
    #table(
      columns: (auto, 1fr, auto, 1fr),
      inset: 4pt, stroke: none, align: left + horizon,
      text(8pt, fill: gray)[Criticality], text(8pt)[#f.severity],
      text(8pt, fill: gray)[Status], text(8pt)[#f.status],
      text(8pt, fill: gray)[OWASP/CWE], text(8pt)[#f.owasp · #f.cwe],
      text(8pt, fill: gray)[Confidence], text(8pt)[#f.votes votes · #str(f.confidence)],
      text(8pt, fill: gray)[Auth context], text(8pt)[#f.auth],
      text(8pt, fill: gray)[Location], text(8pt)[#raw(f.endpoint)],
      text(8pt, fill: gray)[Agent], text(8pt)[#raw(f.agent)],
    )
    #v(4pt) #strong[Description / Impact] #linebreak() #text(9pt)[#f.impact]
    #v(4pt) #strong[Proof of Concept] #linebreak() #raw(f.payload)
    #v(3pt) #strong[Evidence] #linebreak() #raw(f.evidence)
    #v(3pt) #strong[Remediation] #linebreak() #text(9pt)[#f.remediation]
  ]
  #v(8pt)
]

// ---- Conclusion ----
#v(6pt)
#line(length: 100%, stroke: 0.5pt + gray)
= Conclusion
#text(10pt)[#meta.conclusion]
