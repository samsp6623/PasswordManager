let data_proto = {
  "App.load_config": { probe_config: "" },
  "Config.add_credentials": { domain: "", password: "", username: "" },
  "Config.delete_credentials": { domain: "" },
  "Config.delete_instance": { domain: "", username: "" },
  "Config.get_credentials": { domain: "" },
  "Config.initialize": {
    encrypt_opt: "",
    filename: "",
    name: "",
    storage_opt: "",
    user_defined_path: "",
  },
  "FernetwPassphrase.initialize": {
    algorithm: "",
    iterations: "",
    passphrase: "",
  },
  "Storage.encryption_setup": { passphrase: "" },
};


// buttons for proper representation at proper time only
let buttons = document.getElementsByClassName("button");
let homeButton = document.getElementById("home")
let blocks = document.getElementsByClassName("block")

// home button click event
function onHomeClick(e) {
  clearRespDiv();
  homeButton.classList.add("hide")
  for (let button of buttons) {
    button.classList.remove("hide")
  }
  for (let block of blocks) {
    block.classList.add("hide")
  }
}
homeButton.onclick = onHomeClick

// click event for Op buttons
function onButtonClick(e) {
  let id = e.target.id
  let blockId = id.replace("-button", "-block")

  // shows home button
  homeButton.classList.remove("hide")

  // hide other buttons
  for (let button of buttons) {
    button.classList.add("hide");
  }

  // hide the other elements
  for (let b of blocks) {
    if (b.id != blockId) {
      continue
    } else {
      b.classList.remove("hide")
    }
  }
}
for (let button of buttons) {
  button.onclick = onButtonClick;
}

// mount the response
let respDiv = document.getElementById("output")
function clearRespDiv() {
  let output = document.createElement("div");
  output.id = "output"
  document.getElementById("output").replaceWith(output);
}

// generates nodes for fetch response
function getResponseNodes(obj, preKey) {
  let node = [];
  for (let [k,v] of Object.entries(obj)) {
    if (Array.isArray(v)) {
      v.forEach(n => {
        let m = getResponseNodes(n, k);
        m.forEach(x => node.push(x));
      })
    } else if (typeof v == "object" ) {
      let q = getResponseNodes(v, k);
      q.forEach(x => node.push(x));
    } else { 
      // for the output node of fetched request
      let a = document.createElement("a")
      let p = document.createElement("p")
      let preNode;
      if (preKey) {
        console.log("prekey", preKey);
        p.innerText = preKey + "  |  " + k + " :  "
      } else {
        p.innerText = k + " :  "
      }
      a.innerText = v
      a.onclick = async (e) => {
        await navigator.clipboard.writeText(a.innerText);
        confirmMessage.classList.remove("hide");
        await setTimeout(() => (confirmMessage.classList.add("hide")), 750)
      }

      // for the clipboard button
      let img = document.createElement("img");
      img.src = "clipboard.svg"
      img.style.height = "25px";
      img.id = "clipboard-icon"
      a.appendChild(img)

      // for the confirmation text
      let confirmMessage = document.createElement("p")
      confirmMessage.innerText = "Text Copied!"
      confirmMessage.id = "confirm-message"
      confirmMessage.classList.add("hide");
      p.appendChild(a)
      p.appendChild(confirmMessage)
      node.push(p);
    }
  }
  return node;
}

// Takes the dataObject and makes HTML Form element like label and input
function parseFields(dataObject, node, fieldName) {
  Object.entries(dataObject).forEach((i) => {
    if (typeof i[1] != "object") {
      fieldName += i[0] + " ";

      let label = document.createElement("label");
      label.className = `${fieldName}` + " label ";
      label.textContent = i[0].split(".").join(" ");

      let input = document.createElement("input");
      input.className = `${fieldName}` + " input ";
      if (!["password", "passphrase"].includes(i[0])) {
        input.type = "text";
      } else {
        input.type = "password";
      }
   
      fieldName = fieldName.replace(i[0] + " ", "");
      node.push(label, input);
    } else {
      fieldName += i[0] + " ";
      parseFields(i[1], node, fieldName);
      fieldName = "";
    }
  });
  return node;
}

// fetch method to get data from server
async function getData(url, data) {
  try {
    const response = await fetch(url, {
      method: "POST",
      body: JSON.stringify(data)
    });
    if (!response.ok) {
      throw new Error(`Response status: ${response.status}`);
    }
    const json = await response.json();
    console.log(json);
    return json
  } catch (error) {
    console.error(error.message);
  }
}

// handles form submit event
async function handleOnSubmit(e) {
  e.preventDefault();
  let obj = new Object();
  let parent = "";
  Object.values(e.target.elements).forEach((item) => {
    if (item.localName != "input") {
      return;
    }
    Object.values(item.classList).forEach((x) => {
      if (!["button", "label", "input"].includes(x)) {
        if (x.includes(".")) {
          if (!obj.hasOwnProperty(x)) {
            obj[x] = new Object();
          }
          parent = x;
        } else {
          obj[parent][x] = item.value;
        }
      }
    });
  });
  let resp = await getData(e.srcElement.action, obj)
  clearRespDiv()
  getResponseNodes(resp, "").forEach(n => document.getElementById("output").appendChild(n))
  return obj;
}

// Generates form as per the keys passed for particular operation
function generateForm(listOfKeys, buttonText, nameOfForm) {
  let form = document.createElement("form");
  form.onsubmit = handleOnSubmit;
  form.id = nameOfForm;
  form.action = "http://localhost:8000/" + nameOfForm;

  let data = new Object();
  for (let key of listOfKeys) {
    data[key] = data_proto[key];
  }

  nodes = parseFields(data, [], "");
  nodes.forEach((n) => form.appendChild(n));

  let btn = document.createElement("button");
  btn.type = "submit";
  btn.className = `${nameOfForm}`;
  btn.innerText = buttonText;

  form.appendChild(btn);
  return form;
}

// Op - Load Config
let loadConfig = document.getElementById("App.load_config-block");
let lcNodes = generateForm(
  ["App.load_config", "Storage.encryption_setup"],
  "Load Config",
  "load-config"
);
loadConfig.appendChild(lcNodes);

// Op - Add Credential
let addCred = document.getElementById("Config.add_credentials-block");
let acNodes = generateForm(
  ["App.load_config", "Storage.encryption_setup", "Config.add_credentials"],
  "Add Credentials",
  "add-credential"
);
addCred.appendChild(acNodes);

// Op - Get Credential
let getCred = document.getElementById("Config.get_credential-block");
let gcNodes = generateForm(
  ["App.load_config", "Storage.encryption_setup", "Config.get_credentials"],
  "Get Credentials",
  "get-credentials"
);
getCred.appendChild(gcNodes);

// Op - Delete Credential
let delCreds = document.getElementById("Config.delete_credentials-block");
let dcNodes = generateForm(
  ["App.load_config", "Storage.encryption_setup", "Config.delete_credentials"],
  "Delete Credentials",
  "delete-credential"
);
delCreds.appendChild(dcNodes);

// Op - Delete Instance
let delIns = document.getElementById("Config.delete_instance-block");
let diNodes = generateForm(
  ["App.load_config", "Storage.encryption_setup", "Config.delete_instance"],
  "Delete Instnace",
  "delete-instance"
);
delIns.appendChild(diNodes);

// Op - Config Initialize
let confIniti = document.getElementById("Config.initialize-block");
let ciNodes = generateForm(
  [
    "Storage.encryption_setup",
    "Config.initialize",
    "FernetwPassphrase.initialize",
  ],
  "Config Initialize",
  "conf-initialize"
);
confIniti.appendChild(ciNodes);

