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

let criticalOrder = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

//<editor-fold desc="process stopwords">
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
    result.forEach(d => {
        if (d.length >= 2) {
            result1.push(d);
        }
    });
    result = result1;
    return result;
}

//</editor-fold>

//<editor-fold desc="extracting data">
let extractors = {
    'vendor': vendorExtractor,
    'vulnerability_type': problemTypeExtractor,
    'description': descriptionExtractor,
    'product': productExtractor
}
let cveTermExtractors = {
    'vendor': cveVendorExtractor,
    'vulnerability_type': cveProblemTypeExtractor,
    'description': cveDescriptionExtractor,
    'product': cveProductExtractor
}

function baseSeverityExtractor(d) {
    return accessChain(d, baseSeverityAccessChain) ? accessChain(d, baseSeverityAccessChain) : accessChain(d, baseSeverityAccessChainV2);
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

function descriptionExtractor(d) {
    let values = d.values;
    let parts = [];
    values.forEach(d => {
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

function problemTypeExtractor(d) {
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

function cveProductExtractor(cve) {
    let products = [];
    let vendors = [];
    vendors = vendors.concat(accessChain(cve, vendorAccessChain));
    vendors.forEach(vd => {
        products = products.concat(vd['product']['product_data'].map(pd => pd['product_name']));
    });
    return products;
}

function productExtractor(d) {
    let products = [];
    d.values.forEach(cve => {
        let prods = cveProductExtractor(cve);
        products = products.concat(prods);
    });
    return products;
}

//</editor-fold>

let cves = null;

function searchCVEs(month, baseSeverity, type, term) {
    let monthFormat = d3.time.format('%b %Y');
    let filteredCVEs = cves.filter(cve => {
        //Date condition
        let date = monthFormat(new Date(cve[dateType]));
        let dateCondition = date === month;
        //baseSeverity condition
        let cveBaseSeverity = baseSeverityExtractor(cve, baseSeverityAccessChain);
        let baseSeverityCondition = cveBaseSeverity === baseSeverity;

        //take all terms for the type
        let allTerms = cveTermExtractors[type](cve);
        let termCondition = allTerms.indexOf(term) >= 0;

        return dateCondition && baseSeverityCondition && termCondition;
    });
    return filteredCVEs;
}

function loadCloudData(viewOption, draw) {
    d3.json(fileName, function (error, rawData) {
        if (error) throw error;
        //filter by years.
        cves = rawData['CVE_Items'];
        let year1 = new Date(year + '-01-01T00:00Z');
        let year2 = new Date((year + 1) + '-01-01T00:00Z');
        //Filter by date
        cves = cves.filter(d => {
            let date = new Date(d[dateType]);
            return (date >= year1) && (date < year2);
        });
        loadCloudCVEs(viewOption, draw);
    });
}

function loadISPCloudData(viewOption, draw) {
    let fileName = "../data/isp1.json";
    // let fileName = "../data/allCVEs.json";
    d3.json(fileName, function (error, rawData) {
        if (error) throw error;
        cves = rawData;
        // //Filter date
        // let year1 = new Date(2010 + '-01-01T00:00Z');
        // let year2 = new Date((2018 + 1) + '-01-01T00:00Z');
        // //Filter by date
        // cves = cves.filter(d => {
        //     let date = new Date(d[dateType]);
        //     return (date >= year1) && (date < year2);
        // });
        loadCloudCVEs(viewOption, draw);
    });
}

function loadISPData() {
    loadISPCloudData("vendors", draw)
}

function loadData() {
    year = +$("#cveYear").val();
    fileName = "nvdcve-1.0-" + year;
    fileName = "../data/" + fileName + ".json";
    loadCloudData("vendors", draw);
}

function modifiedCVEsToOriginalCVEs(theCves) {
    return theCves.map(d => d['originalCVE']);
}

let termSelector;//put this as global since will use it in different place.
function processViewOptions() {
    //Only do it if we haven't got the counts
    if (!cloudViewOptions[0].count) {
        //We count terms for all the options
        let data = processCloudData(cloudViewOptions.map(d=>d.key));
        let allText = [];
        data.forEach(timeStep => {
            allText = allText.concat(_.flatten(d3.values(timeStep.topics).map(topic => topic.text)));
        });
        cloudViewOptions.forEach(viewOption => {
            let count = 0;
            allText.forEach(text => {
                if (text.type === viewOption.key) {
                    count = count + 1;
                }
            });
            viewOption.count = count;
        });
        //Create the legend for the first time. Next we will only update the view + call the loadCloudCVEs again.
        termSelector = new TermSelector("viewTypeSelect", cloudViewOptions, loadCloudCVEs);
        termSelector.create_legend();
    }
}

function processCloudData(viewOptions) {
    let monthFormat = d3.time.format('%b %Y');
    var data = d3.nest().key(d => monthFormat(new Date(d[dateType]))).entries(cves);
    data = data.map(d => {
        d.date = d.key;
        d.totalFrequencies = d.values.length;
        let nestedTopics = d3.nest().key(d => baseSeverityExtractor(d)).entries(d.values);
        //Filter the null key
        nestedTopics = nestedTopics.filter(d => d.key !== 'null');
        let topics = nestedTopics.map(d => {
            let frequency = d.values.length;
            let key = d.key;
            let text = [];
            viewOptions.forEach(viewOption => {
                let singleViewOptionText;
                let allTerms = extractors[viewOption](d);
                //Count frequencies
                let counts = allTerms.reduce(function (obj, word) {
                    if (!obj[word]) {
                        obj[word] = 0;
                    }
                    obj[word]++;
                    return obj;
                }, {});
                //Convert to array of objects
                singleViewOptionText = d3.keys(counts).map(function (d) {
                    return {
                        text: d,
                        frequency: counts[d],
                        topic: key,
                        type: viewOption
                    }
                }).sort(function (a, b) {//sort the terms by frequency
                    return b.frequency - a.frequency;
                }).filter(function (d) {
                    return d.text;
                });//filter out empty words
                singleViewOptionText = singleViewOptionText.slice(0, Math.min(singleViewOptionText.length, 45));
                text = text.concat(singleViewOptionText);
            });
            text = _.shuffle(text);
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
    return data;
}

function loadCloudCVEs(viewOptions, draw) {
    if (!cves || cves.length == 0) {
        draw(null);
        return;
    }
    var data = processCloudData(viewOptions);
    //TODO: This is a quick fix => trick by calculating this for the first time => so if first time we do not load 4 options => need to do this calculation separately.
    //Calculate the view options if it is not calculated.
    //For the first time it will load all four view options and also it will not have count frequencies => so we will calculate this
    processViewOptions();
    draw(data);
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