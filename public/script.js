const apiUrl = "http://localhost:3000";
let token = null;

const registerBtn = document.getElementById("registerBtn");
const loginBtn = document.getElementById("loginBtn");
const sendBtn = document.getElementById("sendBtn");

registerBtn.onclick = async () => {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  const res = await fetch(`${apiUrl}/api/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  alert(data.message || "Registered!");
};

loginBtn.onclick = async () => {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  const res = await fetch(`${apiUrl}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  if (data.token) {
    token = data.token;
    document.querySelector(".auth").style.display = "none";
    document.querySelector(".chat").style.display = "block";
  } else {
    alert("Invalid credentials");
  }
};

sendBtn.onclick = async () => {
  const msg = document.getElementById("messageInput").value;
  await fetch(`${apiUrl}/api/messages`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ text: msg }),
  });
  document.getElementById("messageInput").value = "";
  loadMessages();
};

async function loadMessages() {
  const res = await fetch(`${apiUrl}/api/messages`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await res.json();
  const box = document.getElementById("messages");
  box.innerHTML = "";
  data.forEach((m) => {
    const div = document.createElement("div");
    div.textContent = `${m.username}: ${m.text}`;
    box.appendChild(div);
  });
}
