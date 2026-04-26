<span class="chapter-banner">Chapter 15</span>
# AI Security
pic

**Objectives**
1. TBD

Intro

## Big Data

> [!activity] Activity 15.1 - Apache Airflow DAG
> Apache Airflow directed acyclic graph's (DAG) are Python code that defines a workflow definition.  They are comprised of tasks and are scheduled and monitored within Airflow.  They are frequently used to automate extraction, transform, and load (ETL) flows and support big data operations.  In this activity, we'll install and configure an Apache Airflow server within the Ubuntu VM.  We'll then create and run a DAG that handles sensitive information.
> 
> I start by updating the Ubuntu system and then installing some of the Python related prerequisites.
> ```bash
> sudo apt update -y
> sudo apt install -y python3 python3-venv python3-pip
> ```
> ![[../images/15/activity1-prereq.png|Installing Prerequisites|550]]
> Next, I create the project folder and configure the Python virtual environment.
> ```bash
> mkdir -p ~/airflow-lab 
> cd ~/airflow-lab 
> python3 -m venv .venv 
> source .venv/bin/activate 
> ```
> ![[../images/15/activity1-venv.png|Python Virtual Environment|550]]
> Then, I configure the Airflow directory and install Apache Airflow.
> ```bash
> export AIRFLOW_HOME=$HOME/airflow 
> mkdir -p "$AIRFLOW_HOME" 
>
> pip install "apache-airflow== 3.1.8" --constraint "https://raw.githubusercontent.com/apache/airflow/constraints-3.1.8/constraints-3.10.txt"
> ```
> ![[../images/15/activity1-airflow_install.png|Installing Airflow|550]]
> Once Airflow is installed, I install Faker and Graphwiz which will be used to generate some test data.
> ```
> pip install requests Faker graphviz 
> ```
> ![[../images/15/activity1-faker_install.png|Installing Faker|550]]
> The following command starts Airflow in standalone mode.  A continuous log output is displayed that includes a default username and password in the first dozen or so events.
> ```bash
> airflow standalone
> ```
> ![[../images/15/activity1-creds.png|Starting Airflow Credentials|550]]
> Once Airflow fully starts I can log into the console by opening Firefox and navigating to `localhost:8080`.
> ![[../images/15/activity1-console.png|Airflow Console|550]]
> Now I'm ready to start creating my first DAG.  I open another terminal, activate the Python environment, set the Airflow environment variable, and create a couple directories that will hold my custom DAGs and data.
> ```bash
> cd ~/airflow-lab 
> source .venv/bin/activate 
> export AIRFLOW_HOME=$HOME/airflow 
> mkdir -p "$AIRFLOW_HOME/dags" 
> mkdir -p "$AIRFLOW_HOME/data" 
> ```
> ![[../images/15/activity1-folders.png|Creating Airflow Folders|550]]
> I copy the `etl.py` file, which is included within this textbook's file resources, to the `~/airflow/dags/` folder.  This DAG Python file includes a configuration and defines tasks for extract, enrich, transform, load, and pipeline wiring.
> ![[../images/15/activity1-dag3.png|etl.py Loaded|550]]
> After a moment, Airflow will automatically detect the `etl.py` DAG file and will appear automatically on the Dags page.  It can be found by searching "etl".
> ![[../images/15/activity1-dagloaded.png|DAG ETL Loaded|600]]
> Next, I enable and run the DAG by hitting the enable switch and the play button which launches the DAG's configurations.  I simply hit the Trigger button to launch the DAG.
> ![[../images/15/activity1-dagstart.png|Launching ETL DAG|550]]
> The DAG takes about a minute to complete with the latest run's results appearing in the Dag list.  Clicking into the Latest Run shows that all tasks where successfully completed.
> ![[../images/15/activity1-dagsuccess.png|DAG Tasks Successful|600]]
> Each of these tasks output some data files into the `airflow/data/` folder created earlier.  Upon successfully running the ETL DAG, I find several data files.  Looking into the output from the enrich task I can see it contains sensitive PII which may violate company security policies.
> ```bash
> cd ../airflow/data/
> head enriched_users.json
> ``` 
> ![[../images/15/activity1-pii.png|PII Discovered|550]]
> Studying the users.db, created by the load task where the data is ready to be consumed by users, we see restricted PII like email addresses and phone numbers.
> ![[../images/15/activity1-db.png|PII Leak Into users.db|550]]


>[!activity] Activity 15.2 - Sanitizing DAG Data
> Workflow orchestration platforms like Apache Airflow can process vast amounts of data.  These systems are often subject to, or are required to enforce, data restriction requirements.  Examples of requirements include, but are not limited to, removing or sanitizing personally identifiable information (PII) or other sensitive data types.  In this activity, we'll continue from the previously installed Apache Airflow server on the Ubuntu VM and add a task that uses Microsoft's Presidio data loss prevention (DLP) tool to remove sensitive data within the DAG.
> 
> I navigate back to my airflow-lab folder, start the Python virtual environment, and install Presidio.
> ```bash
> cd airflow-lab
> source ~/airflow-lab/.venv/bin/activate 
 >pip install presidio_analyzer presidio_anonymizer 
> ```
> ![[../images/15/activity2-presidio.png|Installing Presidio|550]]
> After Presidio is installed, I install the Spacy module to use its natural language processing within Presidio.
> ```bash
> python -m spacy download en_core_web_lg
> ```
> ![[../images/15/activity2-spacy.png|Installing Spacy|550]]
> Instead of replacing the existing dag/etl.py, I will copy and then modify it so that PII is sanitized using Presidio.  The first step is to copy the file into a new file called etl_secure.py.
> ```bash
> cd ../airflow/dags
> cp etl.py etl_secure.py
> ```
> ![[../images/15/activity2-copyetl.png|Creating etl_secure.py|550]]
> Next, I open etl_secure.py using vim and change the DAG_ID to "etl_secure" and the DATA_PREFIX to "users_secure" within the configuration section.  This will ensure the new ETL will have a unique name and output files.
> ![[../images/15/activity2-config.png|Configuration Changes|550]]
> While still in the etl_secure.py file's configuration section, I add the following configurations that will be used in a Presidio related task to be added later in the file.
> ```python
> # DLP-specific config 
> REDACTED_FILE = f"redacted_{DATA_PREFIX}.json" 
> FINDINGS_FILE = f"dlp_findings_{DATA_PREFIX}.json" 
> FIELDS_TO_SCAN = [ "name","email","phone","fake_phone","notes"] 
> ```
> ![[../images/15/activity2-dlpconfig.png|DLP Configuration Added|550]]
> With the configuration section updated, I add the following task (dlp_redact) between the transform and load tasks.  This code uses Presidio to scan each record based on the detectors defined in FIELDS_TO_SCAN and stores any findings into the FINDINGS_FILE.  The task also redacts any values that match the FIELDS_TO_SCAN and stores the results in the REDACTED_FILE. 
> ```python
>    #------------------------
 >   # DLP
>    # ------------------------
>    from presidio_analyzer import AnalyzerEngine 
 >   from presidio_anonymizer import AnonymizerEngine 
 >   @task 
 >   def dlp_redact(records: list[dict]) -> list[dict]: 
 >       os.makedirs(DATA_DIR, exist_ok=True) 
 >       analyzer = AnalyzerEngine() 
 >       anonymizer = AnonymizerEngine() 
 >       redacted_records = [] 
 >       findings_report = [] 
 >       for r in records: 
 >           new_r = dict(r) 
 >           record_findings = { 
 >               "source_id": r.get("source_id"), 
 >               "fields": {} 
 >           } 
 >           for field in FIELDS_TO_SCAN: 
 >               value = new_r.get(field) 
 >               if value is None: 
 >                   continue 
 >               text = str(value) 
 >               results = analyzer.analyze( 
 >                   text=text, 
 >                   language="en" 
 >               ) 
 >               # Store findings 
 >               record_findings["fields"][field] = [ 
 >                   { 
 >                       "entity_type": res.entity_type, 
 >                       "start": res.start, 
 >                       "end": res.end, 
 >                       "score": res.score, 
 >                       "text": text[res.start:res.end], 
 >                   } 
 >                   for res in results 
 >               ] 
 >               # Apply redaction 
 >               if results: 
 >                   anonymized = anonymizer.anonymize( 
 >                       text=text, 
 >                       analyzer_results=results 
 >                   ) 
 >                   new_r[field] = anonymized.text 
 >           new_r["pii_findings"] = record_findings["fields"] 
 >           redacted_records.append(new_r) 
 >           findings_report.append(record_findings) 
 >       # Save outputs using config variables 
 >       redacted_path = os.path.join(DATA_DIR, REDACTED_FILE) 
 >       with open(redacted_path, "w", encoding="utf-8") as f: 
 >           json.dump(redacted_records, f, indent=2) 
 >       findings_path = os.path.join(DATA_DIR, FINDINGS_FILE) 
 >       with open(findings_path, "w", encoding="utf-8") as f: 
 >           json.dump(findings_report, f, indent=2) 
 >       return redacted_records 
 > ```
 > Finally, I update the etl_secure.py calling logic at the end of the file to wrap the transform task with the newly added dlp_redact task prior to the load task being called.  This will ensure only safe or redacted data is loaded into the database.
 > ![[../images/15/activity2-wrap.png|Update Calling Logic|550]]
 > Now that the secured ETL has been created, it should show up as an available Dag within Airflow.
 > ![[../images/15/activity2-airflowdag.png|etl_secure Dag Available in Airflow|550]]
 > Just like the previous activity, I enable the etl_secure Dag, press the play (run) icon, and then press the trigger button to start the DAG.  After about a minute, the DAG completes all tasks, including the dlp_redact task, successfully.
 > ![[../images/15/activity2-dagsuccess.png|Successful DAG Run|550]]
 > Now, within the users_secure.db file, I can see that email addresses and phone numbers have been redacted!
 > ![[../images/15/activity2-redacted.png|Redacted PII|550]]
## Machine Learning

## Large Language Models

>[!activity] Activity 15.3 - Bypassing Prompt Injection Guardrail
## Agentic AI

>[!activity] Activity 15.4 - Malicious Skill

## Summary

## Exercises

>[!exercise] Exercise 15.1 - Data Detection and Masking
>Some words
>#### Step 1 - Install Airflow
>#### Step 2 - Create DAG
>#### Step 3 - Secure DAG
>#### Step 4 - Analyze Results

>[!exercise] Exercise 15.2 - Bypassing Prompt Injection Guardrail
>Some words
>#### Step 1 - Set Up Model
>#### Step 2 - Create Server
>#### Step 3 - Test the Guardrail

>[!exercise] Exercise 15.3 - Malicious Skill
>Some words
>#### Step 1 - Stage Attack
>#### Step 2 - Set Up Victim
>#### Step 3 - Trigger Attack