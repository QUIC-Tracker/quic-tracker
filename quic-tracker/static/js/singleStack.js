(function( $ ) {
	$.fn.singleStack = function(graphData) {
		//defaults
		var defaults = {
			graph: {
				className: '',
				clickEvent: function(e){},
				slices: {
					className: ''
				}
			},

			viewport: {
				className: '',
				listContainer: {
					className: ''
				}
			},

			series:{
				clickEvent: function(e){},
				data: []
			}
		};
		//merge recursively with supplied data
		$.extend(true, defaults, graphData);
		//copy merged to data
		graphData = defaults;
		var total = 0,
			viewportElement = $("."+graphData.viewport.className),
			sliceClassNames = graphData.graph.slices.className;

		//throw error if not div element
		if(!(this.is('div'))) throw new Error('Element attached is not a div element.');
		//warn if no viewport is available
		if(viewportElement.length === 0) throw new Error('No viewport available');
		//throw error if data is not array
		if(!($.isArray(graphData.series.data))) throw new Error('Data inputted is not an array');
		//warn if data has no elements
		if(graphData.series.length === 0) console.warn('Array inputted is not an array');

		//add styles to div
		this.addClass('single-stack-bar-container');
		this.addClass(graphData.graph.className);
		viewportElement.addClass('single-stack-bar-stats');

		//Add click event
		this.click(graphData.graph.clickEvent);

		//Add list container
		viewportElement.append('<ol class="'+graphData.viewport.listContainer.className+'"></ol>');

		//get total
		for (var i = graphData.series.data.length - 1; i >= 0; i--) {
			total += parseFloat(graphData.series.data[i].y);
		}

		for (var j = 0; j < graphData.series.data.length; j++) {
			var percentage = ((graphData.series.data[j].y/total)*100).toFixed(2);
			//append to graph proper
			this.append('<span class="single-stack-slice '+sliceClassNames+'" style="width:'+percentage+'%; background-color:'+graphData.series.data[j].color+';" title="' + graphData.series.data[j].y + '">'+graphData.series.data[j].name+'</span>');
			// append to stat bar
			viewportElement.find('ol').append('<li class="single-stack-legend-strip"><span class="single-stack-legend-color" style="background-color:'+graphData.series.data[j].color+'"></span><span class="single-stack-legend-name">'+graphData.series.data[j].name+'</span><span class="percent">'+percentage+'%</span></li>');
		}
		this.find('single-stack-legend-strip').click(graphData.series.clickEvent);
		return this;
	};
}( jQuery ));