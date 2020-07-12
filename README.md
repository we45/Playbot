# RobotFramework for ThreatPlaybook

## Installation

```bash
pip install Playbot
```

## Initialize

```
| Playbot  | test-project  | target-name  | threatplaybook-host  |
```

## Keywords

### Login

```
| login  | email  | password  |
```

### Create Project

```
| create project  |
```

### create target

```
| create target  | url  |
```

### Bandit Results

```
| manage bandit results  | resultsfile  |
```

### NodeJSScan Results

```
| manage nodejsscan results  | resultsfile  |
```

### NPMAudit Results

```
| manage npmaudit results  | resultsfile  | 
```

### OWASP ZAP Results

```
| manage zap results  | resultsfile  | 
```

### Create New Scan

```
| create new scan  | tool-name  |
```


### Create New Vulnerability

```
| create new vulnerability  | vul-dictionary  |
```

Vulnerability Dictionary should have: 
    * name
    * cwe
    * description
    * scan-name
    * target
    * severity (integer, 3,2,1)
    * evidences (array): 
        * name
        * url
        * param

