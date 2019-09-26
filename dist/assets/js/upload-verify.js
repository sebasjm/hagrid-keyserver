const container = document.getElementById("container");
const postform = document.getElementById("postform");
const pleasewait = document.getElementById("pleasewait");
const failed = document.getElementById("failed");
const form = document.getElementById("postform");
const url = form.getAttribute("action");

fetch(url, { method: "POST" })
  .then(result => result.text())
  .then(body => {
    const frag = document.createElement("div");
    frag.innerHTML = body;
    container.appendChild(frag);
    const result = document.getElementById("verification-result");
    if (result !== null) {
      while (result.firstChild) {
        container.appendChild(result.firstChild);
      }
      container.removeChild(frag);
    } else {
        // Leave the full content appended since it'll likely be plain text
    }
    // Hide the pleasewait too
    pleasewait.style.display = "none";
  })
  .catch(err => {
    // On error, hide the 'please wait' and show the 'Something went wrong'
    pleasewait.style.display = "none";
    failed.textContent = failed.textContent + err;
    failed.style.display = "block";
  });
// Hide the form and display the 'please wait' block
postform.style.display = "none";
pleasewait.style.display = "block";
