# GuardianAI: Local AI-Powered Security Response 🚧 **Under Construction**

> [!CAUTION]
> ### 🛡️ Ethical Use & Disclaimer
> This project is strictly for **educational and research purposes**. The author is not responsible for any misuse, damage, or illegal activities. It is designed to demonstrate defensive AI capabilities in a controlled environment.

## 🏗️ System Architecture

- **AI Engine (Python + LangGraph)**: The "Brain" that orchestrates the AI agents
- **Backend (Java Spring Boot)**: The "Backbone" managing data, users, and communication
- **Dashboard (React)**: A web-based management and monitoring interface
- **Mobile App (React Native)**: A mobile application for receiving alerts and performing rapid response actions on the go
- **Local LLM (Ollama)**: Local execution of language models (e.g., Llama 3) for free, private processing

## 🛠️ Prerequisites & Installation

### 1. Core Development Tools
- **Windsurf IDE**: Your primary AI-powered code editor for project management
- **Git**: Version control


### 2. AI Infrastructure (Open Source)
- **Ollama**: Run models like Llama 3 locally without API costs
- **Python (3.10+)**: Development language for AI agents

### 3. Backend & Database
- **Java JDK 21 (OpenJDK)**: The foundation for Spring Boot
- **PostgreSQL**: Relational database for security event logging


### 4. Frontend & Mobile
- **Node.js (LTS)**: Runtime for React and React Native
  - [nodejs.org](https://nodejs.org)
- **Expo Go**: Mobile app (App Store/Google Play) to run code on your device instantly

## 📂 Project Structure

```
/guardian-ai-project
├── /backend-java        # Spring Boot API
├── /ai-agents-python    # LangGraph & Ollama logic
├── /dashboard-react     # React Web App
└── /mobile-app          # React Native (Expo)
```

## 🚀 Quick Setup

### Backend Setup

1. **Database Setup**
   ```sql
   CREATE DATABASE guardian_db;
   ```

2. **Configure Application Properties**
   ```properties
   # Database Configuration
   spring.datasource.url=jdbc:postgresql://localhost:5432/guardian_db
   spring.datasource.username=postgres
   spring.datasource.password=your_database_password
   spring.jpa.hibernate.ddl-auto=update
   ```

3. **Run Backend**
   ```bash
   cd backend-java
   mvn spring-boot:run
   ```

### AI Agents Setup

1. **Install Python Dependencies**
   ```bash
   cd ai-agents-python
   python -m venv venv
   .\venv\Scripts\Activate.ps1  # Windows
   pip install langchain-ollama langchain-core
   ```

2. **Install Ollama and Llama3**
   ```bash
   ollama pull llama3
   ```

3. **Test Security Agent**
   ```bash
   python security_agent.py
   ```

### Frontend Setup

1. **Initialize Mobile Project**
   ```bash
   npx create-expo-app mobile-app
   ```

## 🎯 Example Use Case

1. **Detection**: The Java server detects repeated failed SSH login attempts
2. **Analysis**: The AI Agent (via LangGraph) autonomously researches the source IP and identifies it as a known malicious actor
3. **Action**: The system pushes a high-priority alert to the React Native app on the administrator's mobile device

## 🔑 Database Configuration

The system uses PostgreSQL with the following configuration:

- **Database**: `guardian_db`
- **URL**: `jdbc:postgresql://localhost:5432/guardian_db`
- **Username**: `postgres`
- **Password**: `your_database_password
- **Hibernate DDL**: `update`

## 📊 Security Event Model

The system tracks security events with the following fields:

- `id`: Unique identifier
- `sourceIp`: Source IP address
- `eventType`: Type of security event
- `severity`: Event severity (low, medium, high, critical)
- `timestamp`: Event timestamp
- `status`: Event status

## 🤖 AI-Powered Analysis

The security agent analyzes logs using local Llama3 model and returns:

```json
{
  "is_threat": true,
  "severity": "medium",
  "summary": "Failed login attempt from suspicious IP address"
}
```

## 🔧 API Endpoints

The Spring Boot backend provides RESTful endpoints for:
- Creating and retrieving security events
- Querying events by IP, severity, or time range
- Integrating with AI analysis agents

## 📱 Mobile Alerts

Security alerts delivered to mobile devices with:
- Threat severity indicators
- Quick response actions
- Detailed event information

## 🛡️ Security Features

- Real-time threat detection
- Autonomous IP analysis
- Multi-channel alerting
- Historical event tracking
- Severity-based response protocols



