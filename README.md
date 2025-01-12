# Project Structure

`nvd-collector.py`: Outputs JSON files with vulnerability "metadata" from the NVD database
`github-data-collector.py`: Collects additional data from GitHub API

## Project Plan

The core challenge is teaching the AI to understand code the way a security expert would. One powerful approach is to treat the code like a complex document - break it down into its basic structure (this is what we call Abstract Syntax Tree analysis), and then analyze both the code itself and additional clues like when the commit was made, who made it, and what patterns appear in the changes.

For the actual AI model, you could use an innovative approach combining multiple types of analysis. Think of it like having several experts looking at the code from different angles - one part of your system would look at the structure of the code (using what's called a Graph Neural Network), another would look at patterns in how the code was committed (using LSTM networks), and another would analyze the actual code content (using transformer models, similar to what powers ChatGPT). By combining these different perspectives, your system could make more accurate predictions about whether a commit is malicious.

What makes this approach particularly interesting for ISEF is that you could focus on making the **AI explain its decisions** - having it highlight exactly which parts of the code it finds suspicious and why. This kind of explainability is crucial in security applications and would demonstrate sophisticated thinking about real-world applications.

1. Data Collection Phase:
   - Use the NVDCollector to gather vulnerability data
   - Use CommitAnalyzer to extract commit patterns
   - Collect non-malicious commits as control group

2. Feature Engineering Phase:
   - Process commit history data
   - Create code embeddings using AST analysis
   - Combine metadata features

3. Model Architecture:
   - A graph neural network for code structure
   - LSTM for commit pattern sequences
   - Transformer for code content
   - Ensemble these models together

4. Evaluation:
   - Cross-validation
   - Compare against baseline methods
   - Analyze false positives/negatives

A few tips for your ISEF presentation:

1. Focus on explaining how your system detects patterns **that human security analysts might miss**
2. Demonstrate real examples of detected malicious commits
3. Show how different parts of your model contribute to the final decision
4. Discuss potential real-world applications

## Data I Plan to Collect

1. Attack Pattern Analysis
   - Distribution of CWE (Common Weakness Enumeration) types
   - Attack vector distributions (Network, Local, Physical, etc.)
   - Attack complexity distributions (High vs Low)
   - Correlation between attack vectors and CVSS scores

2. Temporal Patterns
   - Average time between vulnerability publication and fix dates
   - Distribution of malicious commits across different times of day/days of week
   - Seasonal patterns in vulnerability discoveries
   - "Hotspot" periods where multiple vulnerabilities were discovered in close succession

3. Repository Characteristics
   - Distribution of vulnerabilities by repository size/activity level
   - Programming languages involved in vulnerable commits
   - Types of files most commonly modified in vulnerability fixes
   - Directory/file paths that are frequently involved in security issues

4. Commit Patterns
   - Average number of files changed in vulnerability-fixing commits vs regular commits
   - Size of patches (lines added/removed) in fixing commits
   - Common patterns in commit messages for vulnerability fixes
   - Frequency of related commits (multiple commits needed to fix a single vulnerability)

5. Severity Analysis
   - CVSS score distribution details (not just average)
   - Relationship between CVSS scores and:
     - Number of modified files
     - Time to fix
     - Repository characteristics
     - Attack vectors

6. Reference Analysis
   - Types of external references (patches, exploits, articles)
   - Correlation between number of references and severity
   - Percentage of vulnerabilities with public exploits
   - Common reference sources

For your trifold presentation, I'd focus on visualizing:

1. A heat map showing temporal patterns
2. Pie charts of attack vectors and complexity
3. Bar graphs of top CWE types
4. Line graph showing vulnerability trends over time with severity overlay

For model stratification/clustering, pay special attention to:

1. CVSS score distributions to ensure balanced severity representation
2. CWE types to maintain diverse vulnerability categories
3. Repository characteristics to avoid biasing toward certain project types
4. Temporal patterns to ensure your model works across different time periods
5. Attack vectors and complexity to maintain balanced representation of different attack types
