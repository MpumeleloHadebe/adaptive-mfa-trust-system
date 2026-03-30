# System Design Overview

# Architecture
- Flask backend handles authentication logic
- Database stores users, devices, login attempts
- Decision engine evaluates trust level
# Key Components
1. Authentication Service
- Handles login and registration
2. Trust Engine
- Evaluates login risk
- Assigns trust score
3. MFA Handler
- Determines if MFA is required

# Data Flow
1. Login request received
2. User credentials validated
3. Device and login context analysed
4. Trust score calculated
5. Access decision returned
