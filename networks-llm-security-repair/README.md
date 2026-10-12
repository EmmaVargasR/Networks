# Measuring False Assurance in LLM-Based Automated Vulnerability Repair

This project evaluates the phenomenon of **False Assurance** in automated software repair using Large Language Models (LLMs) over real-world Python vulnerabilities from the **Vul4Py** benchmark.

## 1. Installation and Environment Setup
The project runs on an **AWS EC2** instance running Amazon Linux 2023.

```bash
# Clone the repository
git clone [https://github.com/EmmaVargasR/networks-llm-security-repair.git](https://github.com/EmmaVargasR/networks-llm-security-repair.git) vul4py
cd vul4py

# Set up the virtual environment
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install openai
