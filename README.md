<h1 align="center">ARBAC analyser</h1>

<div align="center">

  [![GitHub last commit](https://img.shields.io/github/last-commit/jackroi/ARBAC-analyser?style=for-the-badge)](https://github.com/jackroi/ARBAC-analyser/commits/master)
  [![GitHub issues](https://img.shields.io/github/issues/jackroi/ARBAC-analyser?style=for-the-badge)](https://github.com/jackroi/ARBAC-analyser/issues)
  [![GitHub](https://img.shields.io/github/license/jackroi/ARBAC-analyser?style=for-the-badge)](/LICENSE)

</div>

---

<p align="center">
  ARBAC role reachability verifier.
  <br>
</p>


## 📝 Table of Contents
- [About](#about)
- [Getting Started](#getting_started)
- [Usage](#usage)
- [Built Using](#built_using)
- [Authors](#authors)
- [Acknowledgments](#acknowledgement)


## 🧐 About <a name = "about"></a>

Administrative Role Based Access Control (ARBAC) role reachability verifier.

Role reachability is one of the most useful problem to solve for the security
verification of ARBAC.

Informally, the ARBAC role reachability problem amounts to checking whether the goal role
can be assigned to some user of the system after a number of steps, starting from a certain
user-to-role assignment and applying the rules in the ARBAC policy.

This program parses the specification of an ARBAC role reachability problem and
returns its solution (true or false).
It is meant to analyse small ARBAC policies, and it's not adapt to be used with larger ones.
Note that the role reachability problem is PSPACE-complete.
This project uses some pruning algorithms (forward slicing, backward slicing, and a combination
of both) to simplify the input ARBAC role reachability problem, but pruning it's not sufficient
to obtain satisfactory running times for complex policies.

This project was developed for the "Security 2" course of the Computer Science
master degree programme of Ca' Foscari University of Venice.


## 🏁 Getting Started <a name = "getting_started"></a>

### Prerequisites
- Python (version >= 3.8)
- A python virtualenv (optional, but recommended)

### Installing

1. Clone the repository:

```bash
git clone https://github.com/jackroi/ARBAC-analyser
cd ARBAC-analyser
```

2. Install required packages:

```bash
pip3 install -r requirements.txt
```


## 🎈 Usage <a name="usage"></a>

```bash
python3 arbac-analyser.py [policy.arbac]
```

### Input from file:

```bash
python3 arbac-analyser.py ./policies/policy1.arbac
```

### Input from stdin:

```bash
cat ./policies/policy1.arbac | python3 arbac-analyser.py
```


## ⛏️ Built Using <a name = "built_using"></a>
- [Lark](https://github.com/lark-parser/lark) - Parsing toolkit


## ✍️ Authors <a name = "authors"></a>
- [@jackroi](https://github.com/jackroi) - Implementation


## 🎉 Acknowledgements <a name = "acknowledgement"></a>
- "Security 2" course professor for the project idea and specifications.
