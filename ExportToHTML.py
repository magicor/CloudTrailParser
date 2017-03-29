import cloudtrailparser

def export(myFile, parser):
	createHTML(myFile)
	addScript(myFile)
	addHeader(myFile)
	for event in parser.events():
		aRow = "\t\t<tr><td>"+str(event['event_time'])[:-6]+"</td><td>"+str(event['event_name'])+"</td><td>"+str(event['event_source'])+"</td><td>"+str(event['source_ip'])+"</td><td>"+str(event['user_type'])+"</td><td>"+str(event['user_name'])+"</td><td>"+str(event['invoked_by'])+"</td><td>"+str(event['request'])+"</td><td>"+str(event['response'])+"</td></tr>\n"
		addRow(myFile,aRow)

	addEnd(myFile)


def createHTML(myFile):
	html_script = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>CloudTrailLog Parser</title>"""
	
	Html_file=open(myFile,"w")
	Html_file.write(html_script)
	Html_file.close()


def addScript(myFile):
	html_script="""
    <!-- jQuery -->
    <script src="js/jquery-latest.min.js"></script>
    <script src="js/jquery-ui.min.js"></script>

    <!-- Demo stuff -->
    <link rel="stylesheet" href="css/jq.css">
    <link href="css/prettify.css" rel="stylesheet">
    <link rel="stylesheet" href="css/magnific-popup.css">
    <link rel="stylesheet" href="css/jquery-ui.min.css">
    <script src="js/prettify.js"></script>
    <script src="js/docs.js"></script>
    <script src="js/jquery.magnific-popup.min.js"></script>

    <!-- Tablesorter: theme -->
    <link class="theme default" rel="stylesheet" href="css/theme.default.css">
    <link class="theme blue" rel="stylesheet" href="css/theme.blue.css">
    <link class="theme green" rel="stylesheet" href="css/theme.green.css">
    <link class="theme grey" rel="stylesheet" href="css/theme.grey.css">
    <link class="theme ice" rel="stylesheet" href="css/theme.ice.css">
    <link class="theme black-ice" rel="stylesheet" href="css/theme.black-ice.css">
    <link class="theme dark" rel="stylesheet" href="css/theme.dark.css">
    <link class="theme dropbox" rel="stylesheet" href="css/theme.dropbox.css">
    <link class="theme metro-dark" rel="stylesheet" href="css/theme.metro-dark.css">

    <style id="css">/* wrapper of table 2 */
.wrapper {
    position: relative;
    padding: 0 5px;
    height: 250px;
    overflow-y: auto;
}

/* Magnific popup */
#popup {
    position: relative;
    background: #FFF;
    padding: 20px;
    width: auto;
    max-width: 500px;
    margin: 20px auto;
}
/* Since the popup has a 20px margin, we need to adjust the wrapper position
Note:
 this is only required because we aren't actually attaching the sticky header
 to the #popup, instead we're attaching it to the .mfp-wrap because that
 element scrolls instead of the window
*/
#popup .tablesorter-sticky-wrapper {
    margin-left: 20px;
    margin-top: -20px;
}</style>

    <!-- Tablesorter script: required -->
    <script src="js/jquery.tablesorter.js"></script>
    <script src="js/widget-filter.js"></script>
    <script src="js/widget-stickyHeaders.js"></script>

    <script id="js">$(function(){

    $('.open-popup-link').magnificPopup({
        type: 'inline',
        midClick: true,
        callbacks: {
            open: function () {
                // Will fire when this exact popup is opened
                // this - is Magnific Popup object
                $('#table0').tablesorter({
                    theme: 'blue',
                    headerTemplate : '{content} {icon}', // Add icon for various themes
                    widgets: ['zebra', 'filter', 'stickyHeaders'],
                    widgetOptions: {
                        // jQuery selector or object to attach sticky header to
                        stickyHeaders_attachTo: '.mfp-wrap',
                        stickyHeaders_offset: 0,
                        // caption set by demo button value
                        stickyHeaders_includeCaption: includeCaption
                    }
                });
            }
        }
    });

    $('#table1, .nested, #table3').tablesorter({
        widthFixed : true,
        showProcessing: true,
        headerTemplate : '{content} {icon}', // Add icon for various themes

        widgets: [ 'zebra', 'stickyHeaders', 'filter' ],

        widgetOptions: {

            // extra class name added to the sticky header row
            stickyHeaders : '',
            // number or jquery selector targeting the position:fixed element
            stickyHeaders_offset : 0,
            // added to table ID, if it exists
            stickyHeaders_cloneId : '-sticky',
            // trigger "resize" event on headers
            stickyHeaders_addResizeEvent : true,
            // if false and a caption exist, it won't be included in the sticky header
            stickyHeaders_includeCaption : true,
            // The zIndex of the stickyHeaders, allows the user to adjust this to their needs
            stickyHeaders_zIndex : 2,
            // jQuery selector or object to attach sticky header to
            stickyHeaders_attachTo : null,
            // jQuery selector or object to monitor horizontal scroll position (defaults: xScroll > attachTo > window)
            stickyHeaders_xScroll : null,
            // jQuery selector or object to monitor vertical scroll position (defaults: yScroll > attachTo > window)
            stickyHeaders_yScroll : null,

            // scroll table top into view after filtering
            stickyHeaders_filteredToTop: true

            // *** REMOVED jQuery UI theme due to adding an accordion on this demo page ***
            // adding zebra striping, using content and default styles - the ui css removes the background from default
            // even and odd class names included for this demo to allow switching themes
            // , zebra   : ["ui-widget-content even", "ui-state-default odd"]
            // use uitheme widget to apply defauly jquery ui (jui) class names
            // see the uitheme demo for more details on how to change the class names
            // , uitheme : 'jui'
        }
    });

    /* make second table scroll within its wrapper */
    $('#table2').tablesorter({
        widthFixed : true,
        headerTemplate : '{content} {icon}', // Add icon for various themes

        widgets: [ 'zebra', 'stickyHeaders', 'filter' ],

        widgetOptions: {
            // jQuery selector or object to attach sticky header to
            stickyHeaders_attachTo : '.wrapper' // or $('.wrapper')
        }
    });

});</script>
<script>
$(function() {

    window.includeCaption = true;
    $('.caption').on('click', function(){
        includeCaption = !includeCaption;
        $(this).html( '' + includeCaption );
        $('#table0, #table1, #table2, #table3, .nested').each(function(){
            if (this.config) {
                this.config.widgetOptions.stickyHeaders_includeCaption = includeCaption;
                this.config.widgetOptions.$sticky.children('caption').toggle(includeCaption);
            }
        });
    });

    // removed jQuery UI theme because of the accordion!
    $('link.theme').each(function(){ this.disabled = true; });

    var themes = 'blue default green grey ice black-ice dark dropbox metro-dark',
        i, o = '', t = themes.split(' ');
    for (i = 0; i < t.length; i++) {
        o += '<option value="' + t[i] + '">' + t[i] + '</option>';
    }

    $('select:first')
        .append(o)
        .change(function(){
            var theme = $(this).val().toLowerCase(),
                // ui-theme is added by the themeswitcher
                files = $('link.theme').each(function(){
                    this.disabled = true;
                })
            files.filter('.' + theme).each(function(){
                this.disabled = false;
            });
            $('table')
                .removeClass('tablesorter-' + t.join(' tablesorter-'))
                .addClass('tablesorter-' + (theme === 'black-ice' ? 'blackice' : theme) );
        }).change();

    $('input[type="checkbox"]').click(function() {
        var index = $(this).attr('name').substr(3);
        index--;
        $('table tr').each(function() { 
            $('td:eq(' + index + ')',this).toggle();
        });
        $('th.' + $(this).attr('name')).toggle();
    });

});
</script>"""

	Html_file=open(myFile,"a")
	Html_file.write(html_script)
	Html_file.close()


def addHeader(myFile):
	html_header = """
</head>
<body>

<div id="banner">
    <h1>CloudTrail Log<em>Parser</em></h1>
    <h2>Human Friendly Formater</h2>
    <h3>Understand your log</h3>
</div>

<div id="main">

    <p></p>
    <br>

    <div id="root" class="accordion">

        <h3><a href="#">Notes</a></h3>
        <div>
            <h4>This tool is used for CloudTrail log analysis. Change its JSON format to a readable table format.</h4>
        </div>
    </div>
    </br>
    Choose Theme:
    <select></select>
    <p></p>

    <h3>Select headers to display:</h3>
    <form>
        <div id="checkbox"><input type="checkbox" name="col1" checked="checked" /> Event Time </div>
        <div id="checkbox"><input type="checkbox" name="col2" checked="checked" /> Event Name </div>
        <div id="checkbox"><input type="checkbox" name="col3" checked="checked" /> Event Source </div>
        <div id="checkbox"><input type="checkbox" name="col4" checked="checked" /> Source IP </div>
        <div id="checkbox"><input type="checkbox" name="col5" checked="checked" /> User Type </div>
        <div id="checkbox"><input type="checkbox" name="col6" checked="checked" /> User Name </div>
        <div id="checkbox"><input type="checkbox" name="col7" checked="checked" /> Invoked By </div>
        <div id="checkbox"><input type="checkbox" name="col8" checked="checked" /> Request Elements </div>
        <div id="checkbox"><input type="checkbox" name="col9" checked="checked" /> Response Elements </div>
    </form>
    <table id="table1" class="tablesorter">
    <thead>
            <tr>
            <th  class="col1" data-placeholder="filter">Event Time</th>
            <th  class="col2" data-placeholder="filter">Event Name</th>
            <th  class="col3" data-placeholder="filter">Event Source</th>
            <th  class="col4" data-placeholder="filter">Source IP</th>
            <th  class="col5" data-placeholder="filter">User Type</th>
            <th  class="col6" data-placeholder="filter">User Name</th>
            <th  class="col7" data-placeholder="filter">Invoked By</th>
            <th  class="col8" data-placeholder="filter">Request Elements</th>
            <th  class="col9" filter-false sorter-false">Response Elements</th>
        </thead>
    <tfoot>
        <tr><th>Event Time</th><th>Event Name</th><th>Event Source</th><th>Source IP</th><th>User Type</th><th>User Name</th><th>Invoked By</th><th>Request Elements</th><th>Response Elements</th></tr>
    </tfoot>
    <tbody>
"""

	Html_file=open(myFile,"a")
	Html_file.write(html_header)
	Html_file.close()

def addCheckbox(myFile, row):
	
	Html_file=open(myFile,"a")
	Html_file.write(html_header)
	Html_file.close()

def addRow(myFile, row):
	Html_file=open(myFile,"a")
	Html_file.write(row)
	Html_file.close()

def addEnd(myFile):
	html_end = """
	</tbody>
    </table>
</div>
</body>
</html>"""

	Html_file=open(myFile,"a")
	Html_file.write(html_end)
	Html_file.close()

