let dateType = 'publishedDate';//can be 'lastModifiedDate'
let impactScore = 'impactScore';//can be 'baseScore', 'exploitabilityScore'
let baseScore = 'baseScore';
let exploitabilityScore = 'exploitabilityScore';
let baseMetric = 'baseMetricV3';//can be 'baseMetricV2'
let baseMetricV2 = 'baseMetricV2';
let cvssVersion = 'cvssV3';
let cvssVersionV2 = "cvssV2";
let descriptionAccessChain = ["cve", "description", "description_data"];
let vendorAccessChain = ["cve", "affects", "vendor", "vendor_data"];
let problemTypeAccessChain = ["cve", "problemtype", "problemtype_data"];
let impactScoreAccessChain = ['impact', baseMetric, impactScore];
let exploitabilityScoreAccessChain = ['impact', baseMetric, exploitabilityScore];
let baseScoreAccessChain = ['impact', baseMetric, cvssVersion, baseScore];
let baseSeverity = "baseSeverity";
let baseSeverityAccessChain = ['impact', baseMetric, cvssVersion, baseSeverity];
let baseSeverityAccessChainV2 = ['impact', baseMetricV2, "severity"];
function getOverallScore(d) {
    let is = accessChain(d, impactScoreAccessChain);
    let es = accessChain(d, exploitabilityScoreAccessChain);
    let bs = accessChain(d, baseScoreAccessChain);
    return d3.max([is, es, bs]);
}

let scores = {
    "0-1": [-1, 1],//-1 here since for 0 we would like it to belong to this range too.
    "1-2": [1, 2],
    "2-3": [2, 3],
    "3-4": [3, 4],
    "4-5": [4, 5],
    "5-6": [5, 6],
    "6-7": [6, 7],
    "7-8": [7, 8],
    "8-9": [8, 9],
    "9-10": [9, 10]
};
let criticalOrder = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
let stopWords = ["a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", "but", "by", "can't", "cannot", "could", "couldn't", "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during", "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't", "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here", "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i", "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's", "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", "ours", "ourselves", "out", "over", "own", "same", "shan't", "she", "she'd", "she'll", "she's", "should", "shouldn't", "so", "some", "such", "than", "that", "that's", "the", "their", "theirs", "them", "themselves", "then", "there", "there's", "these", "they", "they'd", "they'll", "they're", "they've", "this", "those", "through", "to", "too", "under", "until", "up", "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were", "weren't", "what", "what's", "when", "when's", "where", "where's", "which", "while", "who", "who's", "whom", "why", "why's", "with", "won't", "would", "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours", "yourself", "yourselves"];
let removeWords = ["object", "Object", "", " ", '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'via', 'can', 'vulnerability', 'allows', 'allow', 'access'];
stopWords = stopWords.concat(removeWords);
function removeStopWords(words, stopWords) {
    let result = [];
    words.forEach(w => {
        if (stopWords.indexOf(w.toLowerCase()) < 0) {
            result.push(w);
        }
    });
    let result1 = [];
    result.forEach(d=>{
        if(d.length>=2){
            result1.push(d);
        }
    });
    result = result1;
    return result;
}


let extractors={
    'vendors': vendorExtractor,
    'problemTypes': problemTypeExtractor,
    'descriptions': descriptionExtractor,
    'products': productExtractor
}
let cveTermExtractors = {
    'vendors': cveVendorExtractor,
    'problemTypes': cveProblemTypeExtractor,
    'descriptions': cveDescriptionExtractor,
    'products': cveProductExtractor
}

function cveDescriptionExtractor(d) {
    let descriptions = accessChain(d, descriptionAccessChain);
    descriptions = descriptions.map(d => d.value);
    let text = descriptions.join(' ');
    let words = text.split(/[ '\-\(\)\*":;\[\]|{},.!?]+/);
    //Remove stopwords
    words = removeStopWords(words, stopWords);
    //Take unique since each cve the frequency is 1.
    words = d3.set(words).values();
    return words;
}

function descriptionExtractor(d){
    let values = d.values;
    let parts = [];
    values.forEach(d=>{
        let words = cveDescriptionExtractor(d);
        parts = parts.concat(words);
    });
    return parts;
};

function cveProblemTypeExtractor(d) {
    let cveProbs = [];
    let probs = accessChain(d, problemTypeAccessChain);
    probs.forEach(prob => {
        prob.description.forEach(desc => {
            cveProbs.push(desc.value);
        });
    });
    return cveProbs;
}

function problemTypeExtractor(d){
    let problemTypes = [];
    d.values.forEach(d => {
        let cveProbs = cveProblemTypeExtractor(d);
        problemTypes = problemTypes.concat(cveProbs);
    });
    return problemTypes;
}

function cveVendorExtractor(cve) {
    let vds = accessChain(cve, vendorAccessChain);
    let vendorPerCVE = vds.map(cve => cve["vendor_name"]);
    return vendorPerCVE;
}

function vendorExtractor(d) {
    let vendors = [];
    d.values.forEach(cve => {
        let vendorPerCVE = cveVendorExtractor(cve);
        vendors = vendors.concat(vendorPerCVE);
    });
    return vendors;
}
function cveProductExtractor(cve){
    let products = [];
    let vendors = [];
    vendors = vendors.concat(accessChain(cve, vendorAccessChain));
    vendors.forEach(vd=>{
        products = products.concat(vd['product']['product_data'].map(pd=>pd['product_name']));
    });
    return products;
}
function productExtractor(d){
    let products = [];
    d.values.forEach(cve=>{
        let prods = cveProductExtractor(cve);
        products = products.concat(prods);
    });
    return products;
}
let cves=null;
function searchCVEs(month, baseSeverity, type, term){
    let monthFormat = d3.time.format('%b %Y');
    let filteredCVEs = cves.filter(cve=>{
        //Date condition
        let date = monthFormat(new Date(cve[dateType]));
        let dateCondition = date===month;
        //baseSeverity condition
        let cveBaseSeverity = accessChain(cve, baseSeverityAccessChain);
        let baseSeverityCondition = cveBaseSeverity === baseSeverity;

        //take all terms for the type
        let allTerms = cveTermExtractors[type](cve);
        let termCondition = allTerms.indexOf(term) >= 0;

        return dateCondition && baseSeverityCondition && termCondition;
    });
    return filteredCVEs;
}
function loadCloudData(viewOption, draw) {
    let topics = d3.keys(scores);
    d3.json(fileName, function (error, rawData) {
        if (error) throw error;
        //Filter data in a year
        let monthFormat = d3.time.format('%b %Y');
        cves = rawData['CVE_Items'];
        let year1 = new Date(year + '-01-01T00:00Z');
        let year2 = new Date((year + 1) + '-01-01T00:00Z');
        //Filter by date
        cves = cves.filter(d => {
            let date = new Date(d[dateType]);
            return (date >= year1) && (date < year2);
        });
        var data = d3.nest().key(d => monthFormat(new Date(d[dateType]))).entries(cves);
        data = data.map(d => {
            d.date = d.key;
            d.totalFrequencies = d.values.length;
            let nestedTopics = d3.nest().key(d => accessChain(d, baseSeverityAccessChain)?accessChain(d, baseSeverityAccessChain): accessChain(d, baseSeverityAccessChainV2)).entries(d.values);
            //Filter the null key
            nestedTopics = nestedTopics.filter(d=>d.key!=='null');
            let topics = nestedTopics.map(d => {
                let frequency = d.values.length;
                let key = d.key;
                let text;
                let allTerms = extractors[viewOption](d);
                //Count frequencies
                var counts = allTerms.reduce(function (obj, word) {
                    if (!obj[word]) {
                        obj[word] = 0;
                    }
                    obj[word]++;
                    return obj;
                }, {});
                //Convert to array of objects
                text = d3.keys(counts).map(function (d) {
                    return {
                        text: d,
                        frequency: counts[d],
                        topic: key
                    }
                }).sort(function (a, b) {//sort the terms by frequency
                    return b.frequency - a.frequency;
                }).filter(function (d) {
                    return d.text;
                });//filter out empty words
                text = text.slice(0, Math.min(text.length, 45));

                d[d.key] = {
                    text: text,
                    frequency: frequency
                };
                delete d.key;
                delete d.values;
                return d;
            });

            d.topics = {};
            topics.sort((a, b) => {
                let topicA = d3.keys(a)[0];
                let topicB = d3.keys(b)[0];
                return criticalOrder.indexOf(topicB) - criticalOrder.indexOf(topicA);
            });

            topics.forEach(topic => {
                for (let key in topic) {
                    d.topics[key] = topic[key];
                }
            });
            delete d.values;
            delete d.key;
            return d;
        }).sort(function (a, b) {//sort by date
            return monthFormat.parse(a.date) - monthFormat.parse(b.date);
        });
        draw(data);
    });
}

function accessChain(obj, chain) {
    let result = obj;
    for (let i = 0; i < chain.length; i++) {
        if (!result) {
            return null;
        }
        result = result[chain[i]];
    }
    return result;
}

function scoreScale(score) {
    let keys = d3.keys(scores)
    for (let i = 0; i < keys.length; i++) {
        let key = keys[i];
        if (score > scores[key][0] && score <= scores[key][1]) {
            return key;
        }
    }
}