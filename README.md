# Project Plan

The core challenge is teaching the AI to understand code the way a security expert would. One powerful approach is to treat the code like a complex document - break it down into its basic structure (this is what we call Abstract Syntax Tree analysis), and then analyze both the code itself and additional clues like when the commit was made, who made it, and what patterns appear in the changes.

For the actual AI model, you could use an innovative approach combining multiple types of analysis. Think of it like having several experts looking at the code from different angles - one part of your system would look at the structure of the code (using what's called a Graph Neural Network), another would look at patterns in how the code was committed (using LSTM networks), and another would analyze the actual code content (using transformer models, similar to what powers ChatGPT). By combining these different perspectives, your system could make more accurate predictions about whether a commit is malicious.

What makes this approach particularly interesting for ISEF is that you could focus on making the **AI explain its decisions** - having it highlight exactly which parts of the code it finds suspicious and why. This kind of explainability is crucial in security applications and would demonstrate sophisticated thinking about real-world applications.

## Project Structure

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

1. Focus on explaining how your system detects patterns that human security analysts might miss
2. Demonstrate real examples of detected malicious commits
3. Show how different parts of your model contribute to the final decision
4. Discuss potential real-world applications
