# Auth  - Django
---
#### Description
Auth project for 'Authentication' Website is built in Python (Django)
#### Requirements
* **Python = 3.5.3**
* Django = 2.0.2 
* django-environ==0.4.5
* pytz = 2018.5
### Configuration Instructions
* **Step 1:** Clone the Git Repository
  `git clone https://github.com/nkscoder/auth_utils.git`
* **Step 2:** CD into that directory
 `cd auth_utils`
* **Step 3:** Install Virtual Env (If not already installed)
 **For Ubuntu:** `sudo apt-get install virtualenv`
 **For MacOS:** `brew install virtualenv`
* **Step 4:** Create a Virtual Environment
  `virtualenv -p python3 venv`
* **Step 5:** Activate Virtual Environment
 `source venv/bin/activate`
* **Step 6:** Install Requirements
 `pip install -r requirements.txt`
* **Step 7:** Create .env file from sample
* **Step 8:** Run Migrations
 `python manage.py migrate`
* **Step 9:** Run Development Server
 `python manage.py runserver`
