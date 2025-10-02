<div align="center">

  <p align="center"><img src="https://github.com/Cursed271/Cursed271/blob/main/Logo.png" width="30%"></a></p>
  <h1>ByteBack</h1>
  
  <p>
    ByteBack decodes F5 BIG‑IP load-balancer cookies to reveal internal IPs, node identifiers, and routing flags.
  </p>
  
  <h4>
    <a href="https://github.com/Cursed271/ByteBack/issues/new?labels=bug&template=bug_report.md">Report Bug</a>
  <span> · </span>
    <a href="https://github.com/Cursed271/ByteBack/issues/new?labels=enhancement&template=feature_request.md">Request Feature</a>
  </h4>

</div>

## 📖 Table of Contents

- [Introduction](#-introduction)
- [Features](#-features)
- [Installation and Usage](#%EF%B8%8F-installation-and-usage)
- [Feedback](#-feedback)
- [Contributors](#-contributors)
- [License](#-license)

## 🚀 Introduction

ByteBack is a Python tool that decodes F5 BIG‑IP load-balancer cookies, extracting internal IP addresses, node identifiers, and flags. Designed for authorized security testing, red-team and purple-team exercises, and forensic analysis, it helps researchers and security professionals safely inspect load-balancer behavior, understand routing, and verify configurations.

<p align="center">
  <h4>ByteBack</h4>
  <img src = "https://github.com/Cursed271/ByteBack/blob/main/ByteBack.png">
</p>

## ✨ Features:

- 🧩 BIG‑IP Cookie Parsing: Recognizes BIGipServer* and related formats, extracting fields.

- 🔐 Decoding Engine: Reveals internal IP addresses, node identifiers, and routing flags.

- 🔍 Traffic Analysis: Helps understand load-balancer behavior and routing decisions.

- 🛠️ Forensic & Testing Utility: Designed for red-team, purple-team, and authorized security research.

- 🚀 Lightweight & Scriptable: CLI-friendly and easy to integrate into automation or analysis workflows.


## ⚙️ Installation and Usage:

1. **Pre-requisites**: Ensure you have Python3 installed on your system.
2. **Clone the Repo**: Use "***git clone https://github.com/Cursed271/ByteBack***"
3. **Traverse into the Directory**: Use "***cd ByteBack***"
4. **Install Dependencies**: Use "***pip3 install -r requirements.txt***"
5. **Execute the Script**: Use "***python3 ByteBack.py***"
6. **Enter target URL or raw BIG‑IP cookie value (When prompted)**

## 💬 Feedback  

Have suggestions or feature requests? Feel free to reach out via:  

- 🐦 **Twitter**: [@Cursed271](https://x.com/Cursed271)  
- 🐙 **GitHub**: [@Cursed271](https://github.com/Cursed271)  
- 🔗 **LinkedIn**: [Steven Pereira](https://www.linkedin.com/in/Cursed271/)  
- 📧 **Email**: [cursed.pereira@proton.me](mailto:cursed.pereira@proton.me)  
- 🐞 **File an Issue**: [GitHub Issues](https://github.com/Cursed271/ByteBack/issues)  
- 💡 **Request a Feature**: [Feature Requests](https://github.com/Cursed271/ByteBack/issues/new?labels=enhancement&template=feature_request.md) 

Your feedback helps improve ByteBack! Contributions and PRs are always welcome. 🚀

## 🙌 Contributors

- **Steven Pereira (aka Cursed)** - Creator & Maintainer  

## 📜 License

ByteBack is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.