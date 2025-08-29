# Overview

ScamShield AI is a cybersecurity analysis application that provides threat detection and safety analysis for URLs, phone numbers, and device security. The application leverages AI-powered analysis through Google's Gemini API to identify potential scams, phishing attempts, and security vulnerabilities. Built with Flask, it offers a web interface for users to submit various types of content for security assessment and receive detailed risk evaluations.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Backend Framework
- **Flask**: Lightweight Python web framework chosen for rapid development and simple deployment
- **Template-based UI**: Server-side rendering using Jinja2 templates for responsive web interface
- **Form-based Input**: Traditional web forms for URL, phone number, and device analysis submissions

## AI Analysis Engine
- **Google Gemini Pro**: Primary AI service for cybersecurity threat analysis and content evaluation
- **Structured Prompting**: Standardized prompt templates requesting classification, risk levels, and security recommendations
- **Multi-input Analysis**: Supports URLs, phone numbers, and basic device security assessments
- **Risk Classification**: Standardized LOW/MEDIUM/HIGH risk levels with detailed explanations

## Data Persistence
- **Firebase Firestore**: NoSQL document database for storing analysis results and historical data
- **Optional Storage**: Application functions without Firebase if credentials are unavailable
- **JSON Document Structure**: Analysis results stored as structured documents with timestamps

## Security Analysis Components
- **URL Analysis**: Domain verification, WHOIS lookups, and Google Safe Browsing integration
- **Phone Verification**: Pattern analysis for scam phone number detection
- **Device Security**: Basic security posture assessment and recommendations
- **External API Integration**: WHOIS API for domain age verification and Google Safe Browsing for URL safety

## Frontend Architecture
- **Bootstrap 5**: Responsive UI framework with dark theme support
- **Progressive Enhancement**: JavaScript for form validation and user experience improvements
- **Icon Integration**: Font Awesome icons for visual consistency
- **Mobile-first Design**: Responsive layout optimized for various screen sizes

## Configuration Management
- **Environment Variables**: Secure API key storage via environment variables
- **Graceful Degradation**: Services function with limited capabilities when API keys are missing
- **File-based Firebase Config**: JSON credentials file for Firebase authentication

# External Dependencies

## AI Services
- **Google Gemini Pro API**: Generative AI for cybersecurity analysis and threat detection
- **API Key**: GEMINI_API_KEY environment variable required for AI analysis functionality

## Security APIs
- **WHOIS API**: Domain registration and age verification service for URL analysis
- **API Key**: WHOIS_API_KEY environment variable required for domain information
- **Google Safe Browsing API**: URL safety verification and malware detection
- **API Key**: GOOGLE_SAFE_API_KEY environment variable required for URL safety checks

## Database Services
- **Firebase Firestore**: Cloud NoSQL database for analysis result persistence
- **Authentication**: firebase_creds.json file required for database access
- **Optional Dependency**: Application functions without Firebase but loses data persistence

## Frontend Dependencies
- **Bootstrap 5**: CSS framework via CDN for responsive design and components
- **Font Awesome**: Icon library via CDN for consistent visual elements
- **Native JavaScript**: No additional frameworks, uses vanilla JavaScript for interactivity