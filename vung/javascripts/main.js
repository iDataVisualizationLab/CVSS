var interpolation = "basis";
var placed = true;
let maxFontSize = 40;
let minFontSize = 8;
let rotateCorner = 15;
let backgroundOpacity = 0.3;
let timeStepFontSize = 10;
let timeStepFontFamily = 'serif';

var cloudSvg = d3.select("#theCloud").append('svg').attr({
    id: "mainsvg"
});

var years = d3.range(2014, 2019, 1);

var initialView = "vendors";
var fileName;
let year = 2017;
//fileName = document.getElementById("datasetsSelect").value;
// fileName = "nvdcve-1.0-2014";
// fileName = "nvdcve-1.0-2015";
// fileName = "nvdcve-1.0-2016";
// fileName = "nvdcve-1.0-2017";
fileName = "isp1";
// fileName = "nvdcve-1.0-2018-1";
// fileName = "nvdcve-1.0-2018";
fileName = "../data/" + fileName + ".json";

class TermSelector {
    constructor(theId, options, handler) {
        this.theId = theId;
        this.excluded_groups = cloudViewOptions.filter(d => d.key === 'description');//description is excluded by default
        this.options = options;
        this.legend = null;
        this.handler = handler;
    }
    getViewOptions(){
        return _.difference(this.options, this.excluded_groups).map(d=>d.key);
    }
    create_legend() {
        let self = this;
        // create legend
        var legend_data = d3.select("#" + this.theId).style("width", "200px").style("overflow", "visible")
            .html("")
            .selectAll(".row")
            .data(this.options)
        // filter by group
        this.legend = legend_data
            .enter().append("div")
            .attr("title", "Toggle group")
            .style("width", "400px")//TODO: May need to make this dynamic
            .on("click", function (d) {
                // toggle group
                if (_.contains(self.excluded_groups, d)) {//Enabling
                    //If enabling description => then need to disable all the other groups.
                    if(d.key==='description'){
                        self.excluded_groups = _.difference(self.options, [d]);
                    }else{//Just exclude the option only.
                        self.excluded_groups = _.difference(self.excluded_groups, [d]);
                        //If enabling other groups => then need to add description to the excluded group.
                        self.excluded_groups = self.excluded_groups.concat(self.options.filter(d=>d.key==='description'));
                    }
                } else {//Disabling
                    self.excluded_groups.push(d);
                    //Handle data here
                }
                self.handleTermSelector();
            });

        this.legend
            .append("span")
            .style("background", function (d, i) {
                return colorNetwork(d.key, 0.85);
            })
            .attr("class", "color-bar");

        this.legend
            .append("span")
            .attr("class", "tally")
            .text(function (d, i) {
                return 0;
            });

        this.legend
            .append("span")
            .text(function (d, i) {
                return " " + d.text;
            });
        this.changeLegendDisplay();
        return this.legend;
    }

    changeLegendDisplay() {
        let maxNumberOfTerms = d3.max(this.options.map(op => op.count));
        this.legend
            .style("text-decoration", d => {
                return _.contains(this.excluded_groups, d) ? "line-through" : null;
            })
            .attr("class", "row");

        this.legend.selectAll(".color-bar")
            .style("width", d => {
                return _.contains(this.excluded_groups, d) ? "0px" : ~~(200 * (d.count / maxNumberOfTerms)) + "px";
            });

        this.legend.selectAll(".tally")
            .text(d => {
                return _.contains(this.excluded_groups, d) ? 0 : d.count;
            });
    }

    handleTermSelector() {
        //Remove all terms.
        this.changeLegendDisplay();
        this.handler(_.difference(this.options, this.excluded_groups).map(d => d.key), draw);
        //Handle the network.
        drawNetwork();
    }
}

let cloudViewOptions = [
    {key: 'vendor', text: 'vendors'},
    {key: 'product', text: 'products'},
    {key: 'vulnerability_type', text: 'problem types'},
    {key: 'description', text: 'description terms'},
];

// function addOptions(controlId, values) {
//     var select = document.getElementById(controlId);
//     for (var i = 0; i < values.length; i++) {
//         var opt = values[i];
//         var el = document.createElement("option");
//         el.textContent = opt;
//         el.value = opt;
//         select.appendChild(el);
//         document.getElementById(controlId).value = initialView;
//     }
// }
//
// addOptions('viewTypeSelect', d3.keys(extractors));
//
//
// function getViewOption() {
//     let theViewTypeSelect = document.getElementById('viewTypeSelect');
//     let option = theViewTypeSelect.options[theViewTypeSelect.selectedIndex].text;
//     return option;
// }

var spinner;
// function loadData(){
//     // // START: loader spinner settings ****************************
//     // var opts = {
//     //     lines: 25, // The number of lines to draw
//     //     length: 15, // The length of each line
//     //     width: 5, // The line thickness
//     //     radius: 25, // The radius of the inner circle
//     //     color: '#000', // #rgb or #rrggbb or array of colors
//     //     speed: 2, // Rounds per second
//     //     trail: 50, // Afterglow percentage
//     //     className: 'spinner', // The CSS class to assign to the spinner
//     // };
//     // var target = document.getElementById('loadingSpinner');
//     // spinner = new Spinner(opts).spin(target);
//     //loadCloudData(initialView, draw);
// }
// // loadData();

function getViewOption() {
    return 'vendors';
}

function loadNewCVEs() {
    cloudSvg.selectAll("*").remove();
    let option = getViewOption();
    loadCloudCVEs(option, draw);
}

function loadNewData() {
    cloudSvg.selectAll("*").remove();
    let option = getViewOption();
    loadCloudData(option, draw);
}

function draw(data) {
    cloudSvg.selectAll("*").transition().duration(1000).style(10e-6).remove();
    let fontStrokeScale = d3.scale.linear().domain([minFontSize, maxFontSize]).range([0.2, 1]);
    var width = 1765;
    var height = 460;
    if (!data || data.length == 0) {
        return;
    }
    //Layout data
    var axisPadding = 0;
    var margins = {left: 0, top: 0, right: 0, bottom: 40};
    var ws = d3.layout.wordStream()
        .size([width, height * 1.1])
        .interpolate(interpolation)
        .fontScale(d3.scale.linear())
        .minFontSize(minFontSize)
        .maxFontSize(maxFontSize)
        .data(data);
    var boxes = ws.boxes();

    //Display data
    var legendFontSize = 12;
    var legendHeight = boxes.topics.length * legendFontSize;
    //set svg data.
    cloudSvg.attr({
        width: width + margins.left + margins.top,
        height: height + margins.top + margins.bottom + axisPadding + legendHeight
    });

    var area = d3.svg.area()
        .interpolate(interpolation)
        .x(function (d) {
            return (d.x);
        })
        .y0(function (d) {
            return d.y0;
        })
        .y1(function (d) {
            return (d.y0 + d.y);
        });
    //Display time axes
    var dates = [];
    boxes.data.forEach(row => {
        dates.push(row.date);
    });

    var xAxisScale = d3.scale.ordinal().domain(dates).rangeBands([0, width]);
    var xAxis = d3.svg.axis().orient('bottom').scale(xAxisScale);
    var axisGroup = cloudSvg.append('g').attr('transform', 'translate(' + (margins.left) + ',' + (height + margins.top + axisPadding + legendHeight) + ')');
    var axisNodes = axisGroup.call(xAxis);
    styleAxis(axisNodes);
    //Display the vertical gridline
    var xGridlineScale = d3.scale.ordinal().domain(d3.range(0, dates.length + 1)).rangeBands([0, width + width / boxes.data.length]);
    var xGridlinesAxis = d3.svg.axis().orient('bottom').scale(xGridlineScale);
    var xGridlinesGroup = cloudSvg.append('g').attr('transform', 'translate(' + (margins.left - width / boxes.data.length / 2) + ',' + (height + margins.top + axisPadding + legendHeight + margins.bottom) + ')');
    var gridlineNodes = xGridlinesGroup.call(xGridlinesAxis.tickSize(-height - axisPadding - legendHeight - margins.bottom, 0, 0).tickFormat(''));
    styleGridlineNodes(gridlineNodes);
    //Main group
    var mainGroup = cloudSvg.append('g').attr('transform', 'translate(' + margins.left + ',' + margins.top + ')');
    var wordStreamG = mainGroup.append('g');

    var topics = boxes.topics;
    mainGroup.selectAll('path')
        .data(boxes.layers)
        .enter()
        .append('path')
        .attr('d', area)
        .style('fill', function (d, i) {
            return color(topics[i], 1);
        })
        .attr({
            'fill-opacity': backgroundOpacity,
            stroke: 'black',
            'stroke-width': 0.3,
            topic: function (d, i) {
                return topics[i];
            }
        }).on('click', function (d, i) {
            let topic = topics[i];
            mainGroup.selectAll('text').filter(t => {
                return t && !t.cloned && t.placed && t.topic === topic;
            }).attr({
                visibility: 'visible'
            });
            //Remove the cloned element
            document.querySelectorAll("g[cloned='true'][topic='" + topic + "']").forEach(node => {
                node.parentNode.removeChild(node);
            });
            //Remove the added path for it
            document.querySelectorAll("path[wordStream='true'][topic='" + topic + "']").forEach(node => {
                node.parentNode.removeChild(node);
            }
        );
    });
    ;
    var allWords = [];
    d3.map(boxes.data, function (row) {
        boxes.topics.forEach(topic => {
            if (row.topics[topic]) {
                allWords = allWords.concat(row.topics[topic].text);
            }
        });
    });
    var c20 = d3.scale.category20b();

    //Color based on term
    var terms = [];
    for (let i = 0; i < allWords.length; i++) {
        terms.concat(allWords[i].text);
    }
    var uniqueTerms = d3.set(terms).values();
    var termColorMap = colorNetwork;
    var descriptionColorMap = d3.scale.ordinal()
        .domain(uniqueTerms)
        .range(c20.range());

    mainGroup.selectAll('g').data(allWords).enter().append('g')
        .attr({
            transform: function (d) {
                return 'translate(' + d.x + ', ' + d.y + ')rotate(' + d.rotate + ')';
            }
        }).append('text')
        .text(function (d) {
            return d.text;
        })
        .attr({
            'font-family': 'Impact',
            'font-size': function (d) {
                return d.fontSize;
            },
            fill: function (d, i) {
                if (d.type === 'description') {
                    return descriptionColorMap(i);
                } else {
                    return termColorMap(d.type);
                }
            },
            'text-anchor': 'middle',
            'alignment-baseline': 'middle',
            topic: function (d) {
                return d.topic;
            },
            visibility: function (d, i) {
                return d.placed ? (placed ? "visible" : "hidden") : (placed ? "hidden" : "visible");
            }
        }).style('opacity', 10e-6).transition().duration(1000).style("opacity", 1.0);
    //Try
    var prevColor;
    //Highlight
    mainGroup.selectAll('text').on('mouseenter', function () {
        var thisText = d3.select(this);
        thisText.style('cursor', 'pointer');
        prevColor = thisText.attr('fill');
        var text = thisText.text();
        var topic = thisText.attr('topic');
        var allTexts = mainGroup.selectAll('text').filter(t => {
            return t && t.text === text && t.topic === topic;
        });
        allTexts.attr({
            stroke: 'red',
            'stroke-width': 0.5
        });
    });
    mainGroup.selectAll('text').on('mouseout', function () {
        var thisText = d3.select(this);
        thisText.style('cursor', 'default');
        var text = thisText.text();
        var topic = thisText.attr('topic');
        var allTexts = mainGroup.selectAll('text').filter(t => {
            return t && !t.cloned && t.text === text && t.topic === topic;
        });
        allTexts.attr({
            stroke: 'none',
            'stroke-width': '0'
        });
    });
    //Click
    mainGroup.selectAll('text').on('click', function () {
        var thisText = d3.select(this);
        var text = thisText.text();
        var topic = thisText.attr('topic');
        var allTexts = mainGroup.selectAll('text').filter(t => {
            return t && t.text === text && t.topic === topic;
        });
        //Select the data for the stream layers
        var streamLayer = d3.select("path[topic='" + topic + "']")[0][0].__data__;
        //Push all points
        var points = Array();
        //Initialize all points
        streamLayer.forEach(elm => {
            points.push({
                x: elm.x,
                y0: elm.y0 + elm.y,
                y: 0//zero as default
            });
        });
        allTexts[0].forEach(t => {
            var data = t.__data__;
            var fontSize = data.fontSize;
            //The point
            var thePoint = points[data.timeStep + 1];//+1 since we added 1 to the first point and 1 to the last point.
            thePoint.y = -data.streamHeight;
            //Set it to visible.
            //Clone the nodes.
            var clonedNode = t.cloneNode(true);
            d3.select(clonedNode).attr({
                visibility: "visible",
                stroke: 'white',
                'stroke-width': fontStrokeScale(+d3.select(clonedNode).attr("font-size")),
                'style': 'cursor: pointer;'
            }).on("click", () => {
                let relatedCves = searchCVEs(data.date, data.topic, data.type, data.text);
                let input = relatedCves;
                var options = {
                    collapsed: true,
                    withQuotes: false
                };
                $('#json-renderer').jsonViewer(input, options);
                $('#jsviewer').css("visibility", "visible");
                var svgRect = document.getElementById("mainsvg").getBoundingClientRect();
                var jsviewer = document.getElementById('jsviewer');
                // jsviewer.style.top = (svgRect.top + svgRect.height + 20) + "px";
                // jsviewer.style.left = (svgRect.left)+"px";
                jsviewer.style.width = (svgRect.width) + "px";

            });
            var clonedParentNode = t.parentNode.cloneNode(false);
            clonedParentNode.appendChild(clonedNode);

            t.parentNode.parentNode.appendChild(clonedParentNode);
            d3.select(clonedParentNode).attr({
                cloned: true,
                topic: topic
            }).transition().duration(300).attr({
                transform: function (d, i) {
                    return 'translate(' + thePoint.x + ',' + (thePoint.y0 + thePoint.y - fontSize / 2) + ')';
                },
            });
        });
        //Add the first and the last points
        points[0].y = points[1].y;//First point
        points[points.length - 1].y = points[points.length - 2].y;//Last point
        //Append stream
        wordStreamG.append('path')
            .datum(points)
            .attr('d', area)
            .style('fill', prevColor)
            .attr({
                'fill-opacity': 1,
                stroke: 'black',
                'stroke-width': 0.3,
                topic: topic,
                wordStream: true
            });
        //Hide all other texts
        var allOtherTexts = mainGroup.selectAll('text').filter(t => {
            return t && !t.cloned && t.topic === topic;
        });
        allOtherTexts.attr('visibility', 'hidden');
    });


    //Build the legends
    var legendGroup = cloudSvg.append('g').attr('transform', 'translate(' + (width - 200) + ',' + (10) + ')');
    var legendNodes = legendGroup.selectAll('g').data(boxes.topics).enter().append('g')
        .attr('transform', function (d, i) {
            return 'translate(' + 10 + ',' + (i * legendFontSize) + ')';
        });
    legendNodes.append('circle').attr({
        r: 5,
        fill: function (d, i) {
            return color(d, 1);
        },
        'fill-opacity': backgroundOpacity,
        stroke: 'black',
        'stroke-width': .5,
    });
    legendNodes.append('text').text(function (d) {
        return d;
    }).attr({
        'font-size': legendFontSize,
        'alignment-baseline': 'middle',
        dx: 8
    });

    // spinner.stop();
    function styleAxis(axisNodes) {
        axisNodes.selectAll('.domain').attr({
            fill: 'none'
        });
        axisNodes.selectAll('.tick line').attr({
            fill: 'none',
        });
        let texts = axisNodes.selectAll('.tick text').attr({
            'font-family': timeStepFontFamily,
            'font-size': timeStepFontSize
        });

        var canvas = document.createElement("canvas");
        var ctx = canvas.getContext('2d');
        ctx.font = timeStepFontSize + "px " + timeStepFontFamily;
        let maxTextWidth = 0;
        let maxTextHeight = timeStepFontSize;
        texts[0].forEach(t => {
            let textWidth = ctx.measureText(t.innerHTML).width;
            if (textWidth > maxTextWidth) maxTextWidth = textWidth;
        });
        //Data length
        let dataLength = boxes.data.length;
        //Available space per data item.
        let availableSpace = width / dataLength;
        if (availableSpace < maxTextWidth) {
            //Rotate the text
            let rotateDeg = Math.atan(maxTextHeight / availableSpace) * 180;
            texts.attr({
                'transform': `rotate(${rotateDeg})`
            })
        }

    }

    function styleGridlineNodes(gridlineNodes) {
        gridlineNodes.selectAll('.domain').attr({
            fill: 'none',
            stroke: 'none'
        });
        gridlineNodes.selectAll('.tick line').attr({
            fill: 'none',
            'stroke-width': 0.7,
            stroke: 'lightgray'
        });
    }

    function color(d, a) {
        var c = colors[d];
        return ["hsla(", c[0], ",", c[1], "%,", c[2], "%,", a, ")"].join("");
    }
};
