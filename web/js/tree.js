if(window.system == undefined) window.system = {};
system.tree = (new class{
    constructor(){
        var that = this;

        this.radius = 1000;
        this.padding = 100;

        this.title = d3.select("#tree-title");

        this.svg = d3.select("#tree")
            .attr("viewBox", "0 0 " + (this.radius+this.padding)*2 + " " + (this.radius+this.padding)*2)
            .attr("preserveAspectratio", "XMidYMid")


        this.svg = this.svg.append("g")
            .attr("transform", "translate(" + (this.radius+this.padding) + "," + (this.radius+this.padding) + ")");

        this.svgOverview = d3.select("#tree-overview")
            .attr("viewBox", "0 0 " + (this.radius+this.padding)*2 + " " + (this.radius+this.padding)*2)
            .attr("preserveAspectratio", "XMidYMid")
            .append("g")
            .attr("transform", "translate(" + (this.radius+this.padding) + "," + (this.radius+this.padding) + ")");
        
        //
        this.legend = d3.select('#tree-legend')
        this.legendMode = 'forkingBlocks'
        this.legendColors = null
        this.forkingBlocks = []
        this.forkingSymbols = []

        this.partition = d3.partition().size([2 * Math.PI, this.radius]);
        this.partitionOverview = d3.partition().size([2 * Math.PI, this.radius]);
       
        this.arc = d3.arc()
            .startAngle((d) => { 
                return d.x0 + 0.01
            })
            .endAngle((d) => { 
                return d.x1 
            })
            .innerRadius((d) => { 
                return d.y0 + (d.data.type == "subtree" ? 60 : 0)
            })
            .outerRadius((d) => {
                return d.y1 - (d.data.type == "subtree" ? -30 : 5)
            });
        

        this.rootNodeId = undefined;
        this.nodes = []
        this.nodesById = {};
        this.nodesElements = {};
        this.overviewNodes = undefined;

        d3.select("nav").select(".title").on("dblclick", () => { this.r()})
    }
    
    drawTree(tree, selectedNodeId){
        var that = this;
        this.title.selectAll("*").remove();
        this.title.append("span").text(selectedNodeId);
        this.rootNodeId = tree.id;
        tree = tree.sum(function(d){
            return ["leaf", "subtree"].includes(d.type) ? 1 : 0
        }).sort(function(a, b) { return b.value - a.value});
        this.partition(tree);
        this.nodes = tree.descendants();
        this.nodesById = {};
        this.nodes.forEach(function(n, i){
            that.nodesById[n.id] = i;
            n.ancestorsId = n.ancestors().map(function(n){ return n.id}).filter(function(id){ return id != n.id});
            n.descendantsId = n.descendants().map(function(n){ return n.id}).filter(function(id){ return id != n.id});
            n.selected = (n.id == selectedNodeId)
            n.svgElement = undefined
        })

        this.svg.selectAll(".treenode")
            .data(this.nodes, function(d){ return d.id})
            .join(
                (enter) => {
                    enter.append("path")
                    .attr("id", function(d){ return d.id})
                        .attr("class", "treenode")
                        
                        .classed("filtered-out", function(d){ return d.data.filteredOut})
                        .classed("filtered-in", function(d){ return !d.data.filteredOut})
                        .classed("leaf", function(d){ return d.data.type == "leaf"})
                        .classed("subtree", function(d){ return d.data.type == "subtree"})
                        .classed("selected", function(d){ return d.selected})
                        .classed("no-selected", function(d){ return !d.selected})

                        .attr("d", that.arc)
                        .on("mouseover", function(d){ that.onNodeMouseover(d) })
                        .on("mouseout", function(d){ that.onNodeMouseout(d) })
                        .on("click", function(d){ that.onNodeClick(d)})
                        .each(function(d){
                            d.svgElement = d3.select(this);
                            that.updateNodesColor([d], true);
                            tippy(this, {
                            content: d.data.id,
                                placement: "top",
                                arrow: true
                            });
                        })
                },
                (update) => {
                    update
                        .classed("filtered-out", function(d){ return d.data.filteredOut})
                        .classed("filtered-in", function(d){ return !d.data.filteredOut})
                        .classed("leaf", function(d){ return d.data.type == "leaf"})
                        .classed("subtree", function(d){ return d.data.type == "subtree"})
                        .classed("selected", function(d){ return d.selected})
                        .classed("no-selected", function(d){ return !d.selected})

                        .each(function(d){
                            d.svgElement = d3.select(this);
                            that.updateNodesColor([d], true);
                        })
                        //.transition().duration(1000)
                        .attr("d", that.arc)
                        //.on("start", () => { })
                        //.on("end", () => { })
                },
                (exit) => {
                    exit.remove()
                }
            );
    }

    onNodeMouseover(d){
        var that = this;
        this.svg.selectAll(".treenode").classed("not-focused", true)
        d.svgElement.classed("focused", true).classed("not-focused", false);
        d.ancestorsId.forEach(function(id){
            that.nodes[that.nodesById[id]].svgElement.classed("focused-ancestor", true).classed("not-focused", false);
        });
    }

    onNodeMouseout(d){
        var that = this;
        this.svg.selectAll(".treenode").classed("not-focused", false)
        d.svgElement.classed("focused", false);
        d.ancestorsId.forEach(function(id){
            that.nodes[that.nodesById[id]].svgElement.classed("focused-ancestor", false);
        });
    }

    onNodeClick(d){
        let nodeId = d.data.type == "subtree" ? d.data.node.id : d.id 
        if(nodeId == this.rootNodeId && d.selected){
            system.state.resetCurrentNode();
        } 
        else system.state.setCurrentNode(nodeId);
    }

    drawTreeOverview(tree, selectedNodeId){
        var that = this;
        if(tree != undefined && tree != null){
            tree = tree.sum(function(d){
                return ["leaf", "subtree"].includes(d.type) ? 1 : 0
            }).sort(function(a, b) { return b.value - a.value});
            this.partitionOverview(tree);
            this.overviewNodes = tree.descendants();
            this.overviewNodes.forEach(function(n, i){
                 n.ancestorsId = n.ancestors().map(function(n){ return n.id}).filter(function(id){ return id != n.id});
                 n.descendantsId = n.descendants().map(function(n){ return n.id}).filter(function(id){ return id != n.id});
             });
            this.svgOverview.selectAll("path").remove();
            this.svgOverview.selectAll()
                .data(this.overviewNodes)
                .enter()
                .append("path")
                .attr("id", function(d){ return d.id})
                .attr("class", "treenode-overview")
                .attr("d", that.arc)
                .each(function(d){
                    d.svgElement = d3.select(this)
                })
        }
       
        this.svgOverview.selectAll("*")
            .classed("selected", function(d){ 
                return d.id == selectedNodeId
            })
            .classed("not-selected", function(d){ 
                return d.id != selectedNodeId
            })
            .classed("selected-ancestor", function(d){ 
                return d.descendantsId.includes(selectedNodeId) && d.id != selectedNodeId
            })
            .classed("selected-descendant", function(d){ 
                return d.ancestorsId.includes(selectedNodeId)  && d.id != selectedNodeId
            })
            .classed("filtered-out", function(d){ 
                return d.data.filteredOut
            })
            .classed("filtered-in", function(d){ 
                return !d.data.filteredOut
            })
    }

    drawTreeLegend() {
      this.legend.selectAll('*').remove()
      system.state.resetSelectedForkingBlocks(false)
      system.state.resetSelectedForkingSymbols(false)
      if (system.state.currentNode === null) {
        this.updateNodesColor(this.nodes)
        return
      }
      const legendHead = this.legend.append('div').attr('id', 'tree-legend-head')
      const legendToggle = legendHead.append('div').attr('id', 'tree-legend-head-toggle')
      const legendList = legendHead.append('div').attr('id', 'tree-legend-head-list')
      legendList.append('div')
          .text(() => {
              if (this.legendMode === 'forkingBlocks') return 'Forking Blocks'
              if (this.legendMode === 'forkingSymbols') return 'Forking Symbols'
          })
      const legendOther = legendList.append('div')
          .style('display', 'none')
          .text(() => {
              if (this.legendMode !== 'forkingBlocks') return 'Forking Blocks'
              if (this.legendMode !== 'forkingSymbols') return 'Forking Symbols'
          })
      legendToggle
          .on('click', () => legendOther.style('display', legendOther.style('display') === 'none' ? 'block' : 'none'))
        .append('i').attr('class', 'fas fa-bars')
      legendOther
        .on('click', () => {
            this.legendMode = this.legendMode === 'forkingBlocks' ? 'forkingSymbols' : 'forkingBlocks'
            this.drawTreeLegend()
        })
      const table = this.legend
        .append('div').attr('id', 'tree-legend-table-container')
        .append('table')
      const tableHead = table
        .append('thead')
        .append('tr')
      table.append('tbody')
      if (this.legendMode === 'forkingBlocks') {
          tableHead.append('th').text('Block').attr('colspan', 2)
          tableHead.append('th').text('Count')
          SYMBOLS_CATS.forEach(c => {
              tableHead.append('th').append('span').append('i').attr('class', `fas ${c.icon}`)
          })
          this.forkingBlocks = system.data.getForkingBlocks(system.state.currentNode, system.state.pathsFilters)
          for (let i = 0; i < 2; i++) {
              if (i >= this.forkingBlocks.length) break
              system.state.addSelectedForkingBlock(this.forkingBlocks[i].blockId, false)
          }
          this.legendColors = system.colors.treeForkingBlocks()
          this.legendColors.domain(this.forkingBlocks.map(b => b.blockId))
      }
      else if (this.legendMode === 'forkingSymbols') {
          tableHead.append('th').text('Symbol').attr('colspan', 2)
          tableHead.append('th').text('Count')
          tableHead.append('th').text('Depth')
          tableHead.append('th').text('Cat')
          tableHead.append('th').text('Filter')
          this.forkingSymbols = system.data.getForkingSymbols(system.state.currentNode, system.state.pathsFilters)
          for (let i = 0; i < 2; i++) {
              if (i >= this.forkingSymbols.length) break
              system.state.addSelectedForkingSymbol(this.forkingSymbols[i].symbolId, false)
          }
          this.legendColors = system.colors.treeForkingSymbols()
          this.legendColors.domain(this.forkingSymbols.map(s => s.symbolId))
      }
      this.updateTreeLegend()
    }

    updateTreeLegend() {
      if (this.legendMode === 'forkingBlocks') {
        const blockRows = this.legend.select('tbody').selectAll('tr')
          .data(this.forkingBlocks.map(d => ({ ...d, selected: system.state.selectedForkingBlocks.indexOf(d.blockId) >= 0 })), d => d.blockId)
        //
        blockRows
          .exit()
          .remove()
        //
        const blockRowsEnter = blockRows
          .enter()
          .append('tr')
            .classed('tree-legend-row', true)
        blockRows.merge(blockRows)
        //
        blockRowsEnter
          .append('td')
            .classed('tree-legend-toggle', true)
          .merge(blockRows.select('.tree-legend-toggle'))
            .style('background-color', d => system.state.selectedForkingBlocks.indexOf(d.blockId) < 0 
              ? 'white'
              : this.legendColors(d.blockId)
            )
            .on('click', d => {
              system.state.selectedForkingBlocks.indexOf(d.blockId) < 0 
                ? system.state.addSelectedForkingBlock(d.blockId) 
                : system.state.removeSelectedForkingBlock(d.blockId)
            })
        blockRowsEnter
          .append('td')
            .classed('tree-legend-block', true)
            .text(d => system.data.getBlockAddressById(d.blockId))
          .merge(blockRows.select('.tree-legend-block'))
        blockRowsEnter
          .append('td')
            .classed('tree-legend-count', true)
            .text(d => d.count)
          .merge(blockRows.select('.tree-legend-count'))
        let blocksCatColor = system.colors.treeBlocksCatColor()
          .domain([0, 
              d3.max(this.forkingBlocks, d => { 
                  let values = []
                  SYMBOLS_CATS.forEach(c => { values.push(d[c.name].length)})
                  return d3.max(values)
              })
          ])
        
        SYMBOLS_CATS.forEach(c => {
          blockRowsEnter
              .append('td')
                  .classed('tree-legend-cat', true)
                  .classed(`tree-legend-${c.name}`, true)
          .merge(blockRows.select(`tree-legend-${c.name}`))
            .style('background-color', d => d[c.name].length === 0
              ? 'white'
              : blocksCatColor(d[c.name].length)
            )
        })        
      }
      else if (this.legendMode === 'forkingSymbols') {
          const symbolRows = this.legend.select('tbody').selectAll('tr')
            .data(this.forkingSymbols.map(d => ({ ...d, selected: system.state.selectedForkingSymbols.indexOf(d.symbolId) >= 0 })), d => d.symbolId)
          //
          symbolRows
            .exit()
            .remove()
          //
          const symbolRowsEnter = symbolRows
            .enter()
            .append('tr')
              .classed('tree-legend-row', true)
          symbolRows.merge(symbolRows)
          //
          symbolRowsEnter
            .append('td')
              .classed('tree-legend-toggle', true)
            .merge(symbolRows.select('.tree-legend-toggle'))
              .style('background-color', d => system.state.selectedForkingSymbols.indexOf(d.symbolId) < 0 
                ? 'white'
                : this.legendColors(d.symbolId)
              )
              .on('click', d => {
                system.state.selectedForkingSymbols.indexOf(d.symbolId) < 0 
                  ? system.state.addSelectedForkingSymbol(d.symbolId) 
                  : system.state.removeSelectedForkingSymbol(d.symbolId)
              })
          symbolRowsEnter
            .append('td')
              .classed('tree-legend-name', true)
              .text(d => d.symbolId)
            .merge(symbolRows.select('.tree-legend-name'))
          symbolRowsEnter
            .append('td')
              .classed('tree-legend-count', true)
              .text(d => d.forkingNodes.length)
            .merge(symbolRows.select('.tree-legend-count'))
          symbolRowsEnter
            .append('td')
              .classed('tree-legend-depth', true)
              .text(d => d.creationDepth ? d.creationDepth : -1)
            .merge(symbolRows.select('.tree-legend-depth'))
          symbolRowsEnter
            .append('td')
              .classed('tree-legend-cat', true)
            .append('span')
            .append('i')
              .attr('class', (d) => `fas ${SYMBOLS_CATS.filter(c => c.name === d.category)[0].icon}`)
            .merge(symbolRows.select('.tree-legend-cat'))
          symbolRowsEnter
            .append('td')
              .classed('tree-legend-filter', true)
            .append('span')
            .append('i')
              .attr('class', (d) => `fas fa-filter`)
            .merge(symbolRows.select('.tree-legend-filter'))
          
      }
      this.updateNodesColor(this.nodes)
    }

    updateNodesColor(nodes){
      this.svg.selectAll('.tree-gradients').remove()
      nodes.forEach(n => {
        n.svgElement.style("fill", null).classed("multiple-forking-blocks", false)
        if (this.legendMode === 'forkingBlocks' && system.state.selectedForkingBlocks.length != 0) {
          if (n.data.type == "subtree") {
            if (n.data.forkingBlocks.length === 1) {
              if (system.state.selectedForkingBlocks.includes(n.data.forkingBlocks[0].blockId)) {
                  n.svgElement.style("fill", this.legendColors(n.data.forkingBlocks[0].blockId))
              }
            }
            else if (n.data.forkingBlocks.length > 1) {
              const blocksIntersection = n.data.forkingBlocks.filter(b => system.state.selectedForkingBlocks.includes(b.blockId))
              const defs = this.svg.append('defs').attr('class', 'tree-gradients')
                const innRad = n.y0 + (n.data.type === 'subtree' ? 60 : 0)
                const outRad = n.y1 - (n.data.type === 'subtree' ? -30 : 5)
                const radGrad = defs.append('radialGradient').attr('id', `${n.id}-gradient`)
                  .attrs({
                      gradientUnits: 'userSpaceOnUse',
                      gradientTransform: `translate(-${this.radius + this.padding}, -${this.radius + this.padding})`,
                      cx: this.radius + this.padding,
                      cy: this.radius + this.padding,
                      fr: innRad,
                      r: outRad
                  })
              if (n.data.forkingBlocks.length <= 3) {
                for (let i = 0; i < n.data.forkingBlocks.length; i++) {
                  radGrad.append('stop')
                    .attrs({
                        'offset': i / n.data.forkingBlocks.length,
                        'stop-color': system.state.selectedForkingBlocks.indexOf(n.data.forkingBlocks[i].blockId) >= 0
                          ? this.legendColors(n.data.forkingBlocks[i].blockId)
                          : this.legendColors('')
                    })
                  radGrad.append('stop')
                    .attrs({
                        'offset': (i + 1) / n.data.forkingBlocks.length,
                        'stop-color': system.state.selectedForkingBlocks.indexOf(n.data.forkingBlocks[i].blockId) >= 0
                          ? this.legendColors(n.data.forkingBlocks[i].blockId)
                          : this.legendColors('')
                    })
                }
              }
              else {
                let i = 0
                while (i < Math.min(blocksIntersection.length, 2)) {
                  radGrad.append('stop')
                    .attrs({
                        'offset': i / 3,
                        'stop-color': this.legendColors(blocksIntersection[i].blockId)
                    })
                  radGrad.append('stop')
                    .attrs({
                        'offset': (i + 1) / 3,
                        'stop-color': this.legendColors(blocksIntersection[i].blockId)
                    })
                  i += 1
                }
                while (i < 3) {
                  radGrad.append('stop')
                    .attrs({
                        'offset': i / 3,
                        'stop-color': this.legendColors('')
                    })
                  radGrad.append('stop')
                    .attrs({
                        'offset': (i + 1) / 3,
                        'stop-color': this.legendColors('')
                    })
                  i += 1
                }
              }
              n.svgElement.style('fill', `url(#${n.id}-gradient)`)
            }
          }
          else {
            if (n.data.forkingBlocks.length != 0 && system.state.selectedForkingBlocks.includes(n.data.forkingBlocks[0].blockId)) {
              n.svgElement.style("fill", this.legendColors(n.data.forkingBlocks[0].blockId))
            }
          }
        }
        if (this.legendMode === "forkingSymbols" && system.state.selectedForkingSymbols.length != 0){
          if (n.data.forkingSymbols.length === 1) {
            if (system.state.selectedForkingSymbols.includes(n.data.forkingSymbols[0].symbolId)) {
              n.svgElement.style("fill", this.legendColors(n.data.forkingSymbols[0].symbolId))
            }
          }
          else if (n.data.forkingSymbols.length > 1) {
            const symbolsIntersection = n.data.forkingSymbols.filter(s => system.state.selectedForkingSymbols.includes(s.symbolId))
            const defs = this.svg.append('defs').attr('class', 'tree-gradients')
            const innRad = n.y0 + (n.data.type === 'subtree' ? 60 : 0)
            const outRad = n.y1 - (n.data.type === 'subtree' ? -30 : 5)
            const radGrad = defs.append('radialGradient').attr('id', `${n.id}-gradient`)
              .attrs({
                  gradientUnits: 'userSpaceOnUse',
                  gradientTransform: `translate(-${this.radius + this.padding}, -${this.radius + this.padding})`,
                  cx: this.radius + this.padding,
                  cy: this.radius + this.padding,
                  fr: innRad,
                  r: outRad
              })
            if (n.data.forkingSymbols.length <= 3) {
              for (let i = 0; i < n.data.forkingSymbols.length; i++) {
                radGrad.append('stop')
                  .attrs({
                      'offset': i / n.data.forkingSymbols.length,
                      'stop-color': system.state.selectedForkingSymbols.indexOf(n.data.forkingSymbols[i].symbolId) >= 0
                        ? this.legendColors(n.data.forkingSymbols[i].symbolId)
                        : this.legendColors('')
                  })
                radGrad.append('stop')
                  .attrs({
                      'offset': (i + 1) / n.data.forkingSymbols.length,
                      'stop-color': system.state.selectedForkingSymbols.indexOf(n.data.forkingSymbols[i].symbolId) >= 0
                      ? this.legendColors(n.data.forkingSymbols[i].symbolId)
                      : this.legendColors('')
                  })
              }
            }
            else {
              let i = 0
              while (i < Math.min(symbolsIntersection.length, 2)) {
                radGrad.append('stop')
                  .attrs({
                      'offset': i / 3,
                      'stop-color': this.legendColors(symbolsIntersection[i].symbolId)
                  })
                radGrad.append('stop')
                  .attrs({
                      'offset': (i + 1) / 3,
                      'stop-color': this.legendColors(symbolsIntersection[i].symbolId)
                  })
                i += 1
              }
              while (i < 3) {
                radGrad.append('stop')
                  .attrs({
                      'offset': i / 3,
                      'stop-color': this.legendColors('')
                  })
                radGrad.append('stop')
                  .attrs({
                      'offset': (i + 1) / 3,
                      'stop-color': this.legendColors('')
                  })
                i += 1
              }
            }
            n.svgElement.style('fill', `url(#${n.id}-gradient)`)
          }
        }
      })
    }

    highlightNodes(nodesId, highlight = true){
        this.nodes.forEach((n) => {
            if(highlight) n.svgElement.style("opacity", (nodesId.includes(n.id)) ? 1 : 0.2)
            else n.svgElement.style("opacity", null)
        });
        this.overviewNodes.forEach((n) => {
            if(highlight) n.svgElement.style("opacity", (nodesId.includes(n.id)) ? 1 : 0.2)
            else n.svgElement.style("opacity", null)
        });
    }

    r(){
      function rotTween() {
        var i = d3.interpolate(0, 3600);
        return function(t) {
            return "rotate(" + i(t) + ")";
        };
      }
      function rotTweenInverse() {
        var i = d3.interpolate(0, -3600);
        return function(t) {
            return "rotate(" + i(t) + ")";
        };
      }
      d3.select("#tree")
        .transition()
        .duration(5000)
        .attrTween("transform", rotTween)
      d3.select("#tree-overview")
        .transition()
        .duration(5000)
        .attrTween("transform", rotTweenInverse) 
    }
}());
