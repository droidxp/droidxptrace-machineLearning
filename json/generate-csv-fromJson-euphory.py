import pandas as pd
import json

pdObj = pd.read_json('nameProposed.json', orient='index')
csvData = pdObj.to_csv(index=False)


#to_be_dropped = ['malignGraphs','methodsAccessedOnlyByMalign','benignGraphContainsMalignGraph','benignGraphs','benign','malign']

#pdObj.drop(columns = to_be_dropped, inplace = True)

pdObj.to_csv('outputNameMalware.csv', index=True)
