# University_LMS
#### Video Demo: https://youtu.be/0LVs_j5jy-E?si=nA0aomeNPeXAB-YT
#### Description: University LMS is a learning management system designed for both organizations and individuals that are looking for a method to provide educational content to their community as well as track their users performance. 
<img width="2225" alt="Screenshot 2024-07-02 at 8 46 09 PM" src="https://github.com/wintfort55/University_LMS/assets/89238727/d54978cb-114e-451e-adc3-b6e6b5609966"><br>

TODO:
- [x] 1. Read this README  👀
- [ ] 2. Download the project file  💾
- [ ] 3. Create a virtual environment on your machine  🤖
- [ ] 4. Install all the requirements from requirements.txt into your virtual environment  🖥️
- [ ] 5. Run the application  😥

> [!Note]
> The application is set to Debug Mode in .env <br>
> If you want to enable the reset password feature, you will need to configure the "Email server settings" in .env <br>
(You can get a mailtrap account for free and add their Flask SMTP settings here)

FILESYSTEM:

- Logs/: Contains a log of all information, errors, etc. that appear in the terminal.<br>
  - dev_error: Is enabled in debug mode
  - error.log: Will be automatically created in production. (Configure the filepath in app.py)<br>
  
- Static/: Contains all static files, images, and documents
  - images/uploads: Destination for all images uploaded in course creation process.
  - logos: Page branding
  - app.js: Javascript code for search bar feature
  - styles.css: Custom styles, otherwise using Bootstrap framework<br>
  
- Templates/: All html templates. Most are using Jinja syntax to extend information from Layout.html
  - admin_dash: This is the admin dashboard where the course creation, editing, and user tracking is displayed. the users, courses, course_records, and programs pages extend off of the admin dash page.
  - apology: I kept the apology template from our cs50 Finance project. This template is used throughout the app for most of the error notifications
  - cigca_central_dash, cigca_east_dash, cigca_north_dash, cigca_south_dash, cigca_west_dash: These are all similar dashboards for users from each of these Programs. (This application is being desiged for a specific project in Africa).
  - coordinator_dash: This is the coordinator dashboard for each of the regional cigca dashboards listed above. Currently the dashboards for each program and coordinator just displays a greeting with the user's name. (Welcome, ___ !)
  - course_detail_record: This is where the admin will be able to view the records for each course and track which users are enrolled, their progress and grade.
  - course_detail: This is the main page for the courses. It populates the information added to the lms.db for each course.
  - course_records: This is the page before the course_detail_record. The admin can view the summary detail relevant to track the course.
  - courses: This page is where the admin can viw all created courses, edit the course, translate the course, and ultimately lead them to view the information within the course sections, lessons, and quiz. This was one of the first major design decisions that I had to make..I chose to use a flag system on the backend that enabeles each of these features (adding a course, editing a course, deleting a course). I felt a flag system would be easier and reduce the amout of html pages.
  - fr_login: This is the french login page. When the user first registers, they are presented with the option to choose their prefered language. After registering, they are presented with this page to login.
  - fr_reset_password: To enable a password reset email in french, I choose to implement a different route for the french users. This page comes after they click the link in their email to reset their password.
  - fr_reset_request: This is the page presented to the french users when they select to reset their password, they will then input the email on this page and the password reset token will be generated and sent to their email if they are a valid user.
  - index: This is the homepage. It is currently enabled just to welcome the user by their name (Welcome, ___ !)
  - instructor_dash: This page is currently set to welcome the instructor by their name (Welcome, ___ !)
  - intro: This page is the introduction title page to this project. (It can be deleted)
  - language: This is the page that loads when the user selects their language preference (if they are already logged in). There is another page to select language preference while registering.
  - layout: The layout page is the backbone to almost every other page in the project. It contains the head, body, and footer.
  - lesson_detail: This is the main page for the lessons. It populates the information added to the lms.db for each lesson and quiz (the quiz is enabled by a modal).
  - lessons: Similar to the courses page, this is where the admin can view all the lessons created, edit the lesson, translate the lesson, and view the lesson information. 
  - login: This is the main login page for english users.
  - pictures: This page is not set up in the navigation bar, but can be accessed using a get request in the url. It displays all the pictures that have been uploaded to the images directory.
  - program_detail: Similar to the course_detail and lesson_detail, this page displays all the Program information stored in the lms.db
  - program_search_courses: This page is extended from the programs page, it displays all the program information as it is being searched for in the program search bar, it was configured using htmx. I read about it online as I was looking for a search functionality and tested it out here. It works very nicely.
  - programs: Similar to the courses, sections, lessons page. This page enables the admin to edit the programs in the lms. Additionally, with the use of flags on the backed, it enables the page to add and remove courses in the program.
  - published_courses: This page displays all the courses that have been published. To publish a course in courses, set the publish=1.
  - quiz: This is the page that allows the admin to view the created quiz for the lesson, add, edit, and remove a quiz. This uses the flag functionality on the backed to enable each of these features.
  - register_lang: This is the page I was referring to in language. This is the first page loaded when a user selects register. Once they set their language on this page, they are directed to either the french or english route to complete their registration. I chose this setup to enable ease of registration in the user's own language. Currently it is only enabled for french and english.
  - register: This is the registration page for both french and english users. It is automatically translated using flask babel. (please read the flask babel documentation for further information on implementing translation if you choose to do so)
  - reset_password: This is the page loaded for english users after they request a password reset link. (please don't forget to configure email if you choose to enable this)
  - reset_request: This is the page that loads when the user selects that they forgot their password. They input their email here and if the email is in the database, it will send them a token to reset their password (valid for one hour).
  - rise_dash: This is a program dashboard for the RISE program. This program is one of the inspirations for the developement of this learning management system.
  - section_detail: This page displays all the section information from the database. Note: If you don't create at least one lesson inside each section, you will get an error page. This is due to how the backend grades the student's progress. Due to the limited time I had to develope this software for the program, it was the simplest solution I felt at the time, but I acknowledge that there is a better solution out there.
  - sections: Similar to the courses, lessons, and program page; this page enables the admin to create, edit, and remove a section. Each of these functions are enabled by a flag system on the backend.
  - upf_dash: This is a dashboard for users of the upf program. Currently all programs cannot be removed or added on the front end, only on the backend. The program titles can be changed in the program edit page, but if you choose to replace the program names, you will want to edit the registration route. Currently it automatically enrolls users that register under the program name.
  - users: The final page displays all the users that have registered. It enables the admind to edit, add, and remove users. All of which again uses a flag system in the backed to enable.<br>

- Translations/: This directory is created to enable the Flask Babel functionallity.
  - en/: This is the directory where the english translations are stored (not used).
  - fr/: THis is the directory where the french translations are stored (used).
    - messages.mo: This file is automatically generated while exporting translations through Flask Babel
    - messages.po: This file is automatically generated but required you to input the translations for each word identified to translate in your pages. This is done by YOU. You will need to ensure the correct syntax for each word you want translated.

> [!Note]
> Flask Babel is configured for all the current pages in the templates directory. <br>
> If you add any more pages or change any information, you will need to follow the flask babel documentation to ensure you generate the translations properly<br>
> https://python-babel.github.io/flask-babel/<br>
      
- app.py: This file contains over 5,000 lines of code. It has all the routes to each page as well as several of the defined functions that some of the routes need in order to function (pun intended). Comments will guide your way.
- babel.cfg: This has two lines of code necessary for the Flask Babel configuration
- helpers.py: This file contains several functions to help with grading, and other important functionality. Once again, comments will guide your way.
- lms.db: This is the sqlite3 database where all the following information is stored:<br>
  - access codes: registration codes for users
  - content: (not being used), was intended to be enabled for each lesson but once I got to lessons I changed directions and added the functionality there.
  - course_grades: where all the course tracking information is stored
  - course_structure: basic setup for the course (on demand, live, both)
  - course_translation: all the translated content in the course (what would appear on course_detail)
  - courses: all the course information (what would appear on course_detail)
  - languages: english, french
  - lesson_grades: all the lesson tracking information, this includes the grades. (Note: Grades from quizes are added here upon completion of lesson, if a quiz is deleted the grade is still in the lesson_grade)
  - lesson_translations: all the translated content in the lesson (what would appear in lesson_detail)
  - lessons:  all the content in the lesson (what would appear in lesson_detail)
  - levels: course level (beginner, intermediate, advanced)
  - program_courses: where the courses added to programs are stored
  - program_enrollment: all users registered under the access code of their program is automatically enrolled in ther program and added to this table
  - program_grades: Where all program tracking and grade information is stored
  - program_translations: all the translated program content in the program (what would appear on program_detail)
  - programs: all the program information
  - question_translations: the translation of all the questions inside of the quiz
  - questions: the question and answers inside of each quiz
  - quiz: the quiz information (The goal was to create the opportunity to add as many questions inside one quiz, currently it is only enabled to allow 3 questions per quiz and 1 quiz per lesson). This was chosen for simplicity as it meets the needs of the current programs.
  - quiz_grades: this is where all the quiz grade and completion information are tracked. They are also reflected in lesson_grades (in the case that a quiz needed to be deleted, this way it doesn't delete the student's grade or progress).
  - quiz_translations: this is where the quiz translations are stored
  - registration: this is where all user id and timestamp information are recorded upon registration to track general registration.
  - roles: this is where all the admin, instructor, coordinators and program user roles are kept. All admin routes are checked to ensure the user is an admin, cross referencing the user sessinon with this table.
  - section_grades: this is where the section grades are updated and tracked
  - section_translations: this is where the translations are stored for each section. (What would appear on section_detail).
  - sections: this is the where all the section information are stored (What would appear on section_detail).
  - user_profiles: this is where the user's language preference is stored upon registering. It is crucial to ensuring they are greeting with the proper dashboard language page when they login. It also keeps their program id and other information.
  - users: this is where all information collected upon registration are stored.<br>
  
  - messages.pot: This file is configured when Flask Babel is enabled. (please refer to flask babel documentation)
  - requirements.txt: This file contains all the application requirements that should be installed insid the venv in order to run this application.
  - wsgi.py: This file is necessary to run the flask application in a production environment
  - Licence: This is an MIT license that enables you to use this program legally
  - README.md: THis is what you are currently reading. (recursive)

> [!Tip]
> If you choose to use this application for a project and feel stuck anywhere, please feel free to reach out! <br>

