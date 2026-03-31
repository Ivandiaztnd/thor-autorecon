cd "...\thor-autorecon\temp-repo"
mkdir docs
copy "C:\Users\Ivan\...\scanme_nmap_org_45_33_32_156_20260330_181712.html" docs\example-report-scanme.nmap.org.html
git add .
git commit -m "Add example report  scanme.nmap.org (200 CVEs, CRVTICO)"
git push
