async function refreshList() {
  const res = await fetch("/blocklist");
  const data = await res.json();
  const list = document.getElementById("list");
  list.innerHTML = "";
  data.forEach(ip => {
    const li = document.createElement("li");
    li.textContent = ip;
    list.appendChild(li);
  });
}

async function addIP() {
  const ip = document.getElementById("ip").value;
  await fetch("/block", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip })
  });
  refreshList();
}

async function delIP() {
  const ip = document.getElementById("ip").value;
  await fetch(`/block/${ip}`, { method: "DELETE" });
  refreshList();
}

refreshList();
