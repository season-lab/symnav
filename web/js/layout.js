if (window.system == undefined) window.system = {}
system.layout = (function() {
    Waves.attach(".menu-toggle", "waves-light");
    Waves.init();
    var that = this;


    this.rightToggle = d3.select(".filters-panel-toggle")
        .on("click", () => {
            if(this.filtersPanel.closed) this.filtersPanel.open();
            else this.filtersPanel.close();
        })
    this.themeToggle = d3.select(".theme-toggle")
        .on("click", () => {
            if(this.theme.isDark) this.theme.light();
            else this.theme.dark();
        })
    d3.select("#continue-limit").on("click", () => {
        let time = d3.select('#time-limit').property('value')
        if (time === '') time = 0
        let memory = d3.select('#memory-limit').property('value')
        if (memory === '') memory = 0
        system.api.continueExploration(time, memory)
    })
    d3.select("#new-limit").on("click", () => {
        let time = d3.select('#time-limit').property('value')
        if (time === '') time = 0
        let memory = d3.select('#memory-limit').property('value')
        if (memory === '') memory = 0
        system.api.continueExploration(time, memory)
    })
    /*
    */
    this.filtersPanel = (function(){
        const div = d3.select("#filters-panel");
        this.closed = true;
        this.open = function(){
            this.closed = false;
            system.paths.hideParCoords()
            div.transition().duration(500)
                .styles({
                    'flex-grow': 2,
                    'padding-right': '0.6rem'
                })
                .on("end", () => {
                    this.afterUpdate()
                })
        }
        this.close = function(){
            this.closed = true;
            this.afterUpdate()
            system.paths.hideParCoords()
            system.filters.updateDataFiltersList()
            div.transition().duration(500)
                .styles({
                    'flex-grow': 0,
                    'padding-right': '0rem'
                })     
                .on("end", () => {
                    this.afterUpdate()
                })
        }
        this.afterUpdate = function(){
            system.paths.updateParCoords()
            system.filters.update()
        }
        return this;
    }).call({})
    /*
    */
    /*
    */
   this.theme = (function(){
        this.isDark = d3.select("body").classed("theme-dark");
        this.dark = function(){
            this.isDark = true
            d3.select("body").attr("class", "theme-dark")
        }
        this.light = function(){
            this.isDark = false
            d3.select("body").attr("class", null)
        }
    return this;
    }).call({})
    
    
    this.lockUI = (block = true, callback) => {
        let page = d3.select("body").select("#block-page");
        if (page.empty()) {
            page = d3.select("body").insert("div",":first-child")
                .attr("id", "block-page")
                .style("display", "none")
                .style("position", "fixed")
                .style("width", "100%")
                .style("height", "100%")
                .style("left", "0")
                .style("top", "0")
                .style("overflow", "hidden")
                .style("background", "#f8f9fa")
                //.style("cursor", "wait")
                .style("z-index", "2000");

            let message = page.append("div")
                .attr("id", "block-message")
                .style("position", "absolute")
                .style("margin", "auto")
                .style("top", "0")
                .style("right", "0")
                .style("bottom", "0")
                .style("left", "0")
                .style("width", "200px")
                .style("height", "80px")
                .style("color", "black")
                .style("padding-bottom", "10px")
                .style("text-align", "center")
                .style("font-style", "bold");
            
            let spinnerDimension = 60;

            let spinner = message.append("p")
                .style("display", "inline-block")
                .style("box-sizing", "border-box")
                .style("position", "absolute")
                .style("top", "50%")
                .style("left", "50%")
                .style("width", spinnerDimension + "px")
                .style("height", spinnerDimension + "px")
                .style("margin-top", parseInt(-spinnerDimension/2) + "px")
                .style("margin-left", parseInt(-spinnerDimension/2) + "px")
                .style("border-radius", "50%")
                .style("border", "3px solid #aaa")
                .style("border-top-color", "#007BFF")
                .style("animation", "spin 1s linear infinite");

            d3.select("head").append("style").text("@keyframes spin {to {transform: rotate(360deg);}}");
        }

        let transitionDuration = 400;

        if(block){
            page.style("opacity", 0)
                .style("display", null)
                .transition()
                .duration(transitionDuration)
                .style("opacity", 1)
                .on("end", function(){
                    if(callback != undefined) callback.call();
                });
        }

        if(!block){
            page.transition()
                .duration(transitionDuration)
                .style("opacity", 0)
                .on("end", function(){
                    page.style("display", "none")
                    if(callback != undefined) callback();
                });
        }
    }
    this.unlockUI = () => {
        d3.select('#block-page').remove()
    }
   return this;
}).call({})