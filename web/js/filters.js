if (window.system == undefined) window.system = {}
system.filters = (function() {
    var that = this;
    this.symbDiv = d3.select("#symb-filters").select(".content");
    this.dataDiv = d3.select("#data-filters").select(".content");

    
    this.updateSymbolicTreeFiltersList = () => {
        this.symbDiv.select("*").remove();
        if(system.layout.filtersPanel.closed) return;
        if(system.state.symbTreeFilters.length == 0) return;

        var data = system.state.symbTreeFilters.map((f, i) => {
            if(f.type == "filter_block"){
                return [
                    f.elementStr,
                    f.mode == "white" ? "Include" : "Exclude",
                    "<button filter-id='" + i + "'><i class='fas fa-trash'></i></button>"
                ]
            }
            if(f.type == "filter_edge"){
                return [
                    f.elementStr,
                    f.mode == "white" ? "Include" : "Exclude",
                    "<button filter-id='" + i + "'><i class='fas fa-trash'></i></button>"
                ]
            }
            if(f.type == "limit_fork"){
                return [
                    f.elementStr,
                    f.num_fork + (f.inverted ? " - inverted" : ""),
                    "<button filter-id='" + i + "'><i class='fas fa-trash'></i></button>"
                ]
            }
            if(f.type == "limit_symbol"){
                return [
                    f.elementStr,
                    "[" + d.min + ", " + d.max + "]",
                    "<button filter-id='" + i + "'><i class='fas fa-trash'></i></button>"
                ]
            }
        });
        var table = this.symbDiv.append("table").attr("id", "symFiltersTable")//.attr("data-order", "[[ 1, \"desc\" ]]");
        table.append("thead")
            .append("tr")
            .selectAll("th")
            .data([
                "Element",
                "Type",
                ""
            ])
            .enter()
            .append("th")
            .html((d) => { return d});
        var tbody = table.append("tbody")
            .selectAll("tr")
            .data(data)
            .enter()
            .append("tr")
            .selectAll("td")
            .data(d => { return d})
            .enter()
            .append("td")
            .html(d => { return d});
        tbody.selectAll("button").on("click", function(){
            var filterId = d3.select(this).attr("filter-id");
            system.state.removeSymbTreeFilter(filterId);
        });
        $("#symFiltersTable").DataTable();
    }
    this.updateDataFiltersList = () => {
        this.dataDiv.selectAll("*").remove();
        if(system.layout.filtersPanel.closed) return;
        
        var data = []
            .concat(system.data.blockWhiteFilters)
            .concat(system.data.blockBlackFilters)
            .concat(system.data.edgeWhiteFilters)
            .concat(system.data.edgeBlackFilters)
            .map((f) => {
                return [
                    //"<span class='f-over' filter-id='" + f.id + "' filter-el='" + f.el + "'>" + f.elementStr() + "</span>",
                    "<span " + ( f.blockId!=undefined ? ("class='f-over' block-id='" + f.blockId + "'") : "") + ">" + f.elementStr() + "</span>",
                    f.type == "white" ? "Include" : "Exclude",
                    f.coverageLoss,
                    f.treeReduction,
                    "<button filter-id='" + f.id + "'><i class='fas fa-plus'></i></button>"
                ]
            });
        if(data.length == 0) return;
        var table = this.dataDiv.append("table").attr("id", "dataFiltersTable")
            .attr("data-order", "[[ 2, \"asc\" ], [ 3, \"desc\" ]]");
        table.append("thead")
            .append("tr")
            .selectAll("th")
            .data([
                "Element",
                "Type", 
                "Coverage<br>Loss", 
                "Tree<br>Reduction", 
                ""
            ])
            .enter()
            .append("th")
            .html((d) => { return d});
        var tbody = table.append("tbody")
            .selectAll("tr")
            .data(data)
            .enter()
            .append("tr")
                .selectAll("td")
                .data((d) => { return d})
                .enter()
                .append("td")
                .html(d => { return d})
        tbody.selectAll("button").on("click", function(){
            var filterId = d3.select(this).attr("filter-id");
            const filters = system.data.blockWhiteFilters
              .concat(system.data.blockBlackFilters)
              .concat(system.data.edgeWhiteFilters)
              .concat(system.data.edgeBlackFilters)
            const filter = filters.filter(f => f.id === filterId)[0]
            if (filter.el === 'block') system.api.filterBlock(filter.blockId, filter.type)
            if (filter.el === 'edge') system.api.filterEdge(filter.srcBlockId, filter.dstBlockId, filter.type)
        });
        tbody.selectAll(".f-over")
        .on("mouseover", function(){
            let blockId = d3.select(this).attr("block-id")
            system.state.highlightNodes(system.data.getBlockById(blockId).nodes)
        })
        .on("mouseout", () => {
            system.state.highlightNodes(null, false)
        });
        $("#dataFiltersTable").DataTable();
    }
    this.update = () => {
        this.updateSymbolicTreeFiltersList();
        this.updateDataFiltersList();
    }
   return this;
}).call({})