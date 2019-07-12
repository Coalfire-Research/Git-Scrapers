#!/usr/bin/env ruby
require 'rubygems'
require 'httparty'
require 'optparse'
require 'cgi'
require 'io/console'
require 'json'
require 'base64'

API_ERR_MSG = "Invalid GitHub API response. Ensure you are authenticated, the rate limit has not been reached, and the resource you are looking for exists."
pwHash = Hash.new(0) # global password list filled if :wl is enabled

def check_auth_resp(resp)
	if !resp.is_a?(Array)
		STDERR.puts API_ERR_MSG
		STDERR.puts resp
		exit
	end
end

def printn(toprint)
	print "#{toprint}\n"
end

def printtn(toprint)
	print "\t#{toprint}\n"
end

def printttn(toprint)
	print "\t\t#{toprint}\n"
end

def pprinttn(key, value)
	print "\t#{key}\t#{value}\n"
end

def pprintttn(key, value)
	print "\t#{key}\t\t#{value}\n"
end

def printh(toprint)
	print "#{toprint}"
		bold = "\033[1;1m"
		reg = "\033[0;0m"
	filename = toprint[/(.\/report\/.*?html)/, 0]
	HTMLOut << "#{toprint}".gsub(bold, "<b>").gsub(reg, "</b>").gsub(/.\/report\/.*mined.html/, "<a href=\"#{filename}\">#{filename}</a>")
end

def printhn(toprint)
	print "#{toprint}\n"
		bold = "\033[1;1m"
		reg = "\033[0;0m"
	filename = toprint[/(.\/report\/.*?html)/, 0]
	HTMLOut << "#{toprint}\n".gsub(bold, "<b>").gsub(reg, "</b>").gsub(/.\/report\/.*mined.html/, "<a href=\"#{filename}\">#{filename}</a>")
end

def printhtn(toprint)
	print "\t#{toprint}\n"
		bold = "\033[1;1m"
		reg = "\033[0;0m"
	filename = toprint[/(.\/report\/.*?html)/, 0]
	HTMLOut << "\t#{toprint}\n".gsub(bold, "<b>").gsub(reg, "</b>").gsub(/.\/report\/.*mined.html/, "<a href=\"#{filename}\">#{filename}</a>")
end

def printhttn(toprint)
	print "\t\t#{toprint}\n"
		bold = "\033[1;1m"
		reg = "\033[0;0m"
	filename = toprint[/(.\/report\/.*?html)/, 0]
	HTMLOut << "\t\t#{toprint}\n".gsub(bold, "<b>").gsub(reg, "</b>").gsub(/.\/report\/.*mined.html/, "<a href=\"#{filename}\">#{filename}</a>")
end

def pprinthtn(key, value)
	print "\t#{key}\t#{value}\n"
		bold = "\033[1;1m"
		reg = "\033[0;0m"
	HTMLOut << "\t#{key}\t#{value}\n".gsub(bold, "<b>").gsub(reg, "</b>")
end

def pprinthttn(key, value)
	print "\t#{key}\t\t#{value}\n"
		bold = "\033[1;1m"
		reg = "\033[0;0m"
	HTMLOut << "\t#{key}\t\t#{value}\n".gsub(bold, "<b>").gsub(reg, "</b>")
end

def github_api_req(url, auth)
	resp = ""
	begin
		if auth[:token]
			resp = HTTParty.get(url, headers: {
				'User-Agent' => UserAgent,
				'Authorization' => "token #{auth[:token]}"
			}).body
		else
			resp = HTTParty.get(url, headers: {
				'User-Agent' => UserAgent
			}, basic_auth: auth ).body
		end
	rescue => e
		STDERR.puts "Network error:\n#{e}\n"
		exit()
	end
	return resp
end

UserAgent = "Proprietary OSINT Tool"
HTMLOut = <<-HTML
<html>
	<head>
		<title>TITLE</title>
		<meta name="generatedwith" content="git-user.rb">
		<meta name="author" content="Patrick Hurd">
	</head>
	<body>
		<pre><code>
HTML
HTMLEnd = <<-HTML
		</code></pre>
	</body>
	<!-- Generated with git-user.rb, created by Patrick Hurd @ Coalfire Federal -->
</html>
HTML

class User
	def initialize(options)
		@options = options
		@username = options[:user]
		@links = {}
		@links[:gh] = "https://api.github.com/users/#{@username}"
		@links[:gist]= "https://api.github.com/users/#{@username}/gists"
		@links[:api] = "https://api.github.com/users/#{@username}/events/public?page="
		@links[:repos] = "https://api.github.com/users/#{@username}/repos?page="
		@info = {}
		@page = 1
	end

	def stackoverflow(name)
		base = "https://stackoverflow.com/users?page="
		filter = "&filter=All&search="
		potential_accounts = []
		search = name ? name : @username
		resp = HTTParty.get("#{base}1#{filter}#{search}", headers: {
			'User-Agent' => UserAgent
		}).body
		# profile link	|	display name	|	location	|	reputation
		users = resp.scan(/user-details">\r\n.*?<a href="(.*?)">(.*?)<\/a>\r\n.*?<span class="user-location">(.*?)<\/span>.*?\r\n.*?\r\n.*?dir="ltr">(.*?)</)
		count = 0
		users.each do |user|
			stack_user = {
				:display_name => user[1],
				:link => "https://stackoverflow.com#{user[0]}",
				:location => user[2],
				:reputation => user[3]
			}
			if count < 10
				# Get additional info from top results
				id = user[0].scan(/(\d*)/)[7][0]
				profile = HTTParty.get("http://api.stackexchange.com/2.2/users/#{id}?site=stackoverflow&filter=!)RvYQaDu4xmx4JA(JIILy)1X", headers: {
					'User-Agent' => UserAgent
				}).body
				profile = JSON.parse(profile)["items"][0]
				stack_user[:url] = profile["website_url"]
				stack_user[:bio] = profile["about_me"]
				stack_user[:bio] = stack_user[:bio].gsub(/(<.*?>)/, '').gsub(/\n/, ' ') if stack_user[:bio]
			end
			potential_accounts.push(stack_user)
			count = count + 1
		end
		potential_accounts
	end

	def repos()
		repos = []
		page = 1
		while true
			resp = github_api_req("#{@links[:repos]}#{page}", @options[:auth])
			if resp.empty? or resp == "[]"
				break
			end
			resp = JSON.parse(resp)
			check_auth_resp(resp)
			resp.each do |repo|
				next if repo["fork"]
				new = {
					:full_name => repo["full_name"],
					:repo => repo["name"],
					:url => repo["html_url"],
				}
				repos.push(new)
			end
			page = page + 1
		end
		repos
	end

	def emails()
		emails = []
		while true
			resp = github_api_req("#{@links[:api]}#{@page}", @options[:auth])
			resp = JSON.parse(resp)
			if resp.empty?
				break
			end
			check_auth_resp(resp)
			# It's possible to get the name from here too
			resp.each do |x|
				next if x["payload"]["commits"] == nil
				arr = x["payload"]["commits"]
				# Getting the length because for merge commits, the last one
				# is the one by our guy actually pushing the external commits
				# to the local repo
				len = arr.length() - 1
				next if len == -1
				if @options[:extra_checking]
					commit_url = x["payload"]["commits"][len]["url"]
					commit = github_api_req(commit_url, @options[:auth])
					commit = JSON.parse(commit)
					next if commit["author"] == nil
					next if commit["author"]["login"] != @username
				end
				emails.push(x["payload"]["commits"][len]["author"]["email"])
			end
			@page = @page + 1
			# Hard limit of 5 pages
			if @page > 5
				break
			end
		end
		emails.uniq
	end

	def gists()
		gistlist=[]
		resp = github_api_req(@links[:gist], @options[:auth])

		resp = JSON.parse(resp)
		check_auth_resp(resp)

		resp.each do |gist|
			new = {
				:id =>gist["id"],
				:url => gist["html_url"],
			}
			gistlist.push(new)
		end
		gistlist
	end

	def get_info()
		profile = github_api_req(@links[:gh], @options[:auth])
		profile = JSON.parse(profile)
		# Special case where check_auth_resp() can't be used
		if profile["message"]
			STDERR.puts API_ERR_MSG
			STDERR.puts profile["message"]
			exit
		end
		display_name = profile["name"]
		@info[:display_name] = display_name if display_name
		@info[:username] = @username
		bio = profile["bio"]
		@info[:bio] = bio if bio
		works_for = profile["company"]
		@info[:works_for] = works_for if works_for
		location = profile["location"]
		@info[:location] = location if location
		public_email = profile["email"]
		if public_email
			@info[:public_email] = public_email
		else
			@info[:public_email] = ""
		end
		public_url = profile["blog"]
		@info[:wizard] = "phurd"
		@info[:public_url] = public_url if public_url
		@info[:repos] = profile["public_repos"]
		@info[:gists] = profile["public_gists"]
		@info[:followers] = profile["followers"]
		@info[:follows] = profile["following"]
		return if !profile["organizations_url"]
		orgs = github_api_req(profile["organizations_url"], @options[:auth])
		orgs = JSON.parse(orgs)
		check_auth_resp(orgs)
		organizations = []
		orgs.each do |x|
			organizations.push(x["login"])
		end
		@info[:organizations] = organizations if organizations
	end

	def print_info()
		bold = "\033[1;1m"
		reg = "\033[0;0m"
		printhn bold + @info[:display_name] if @info[:display_name]
		printhn "https://github.com/" + @info[:username] + reg
		pprinthttn ":bio", @info[:bio]
		pprinthtn ":works_for", @info[:works_for]
		pprinthtn ":location", @info[:location]
		pprinthtn ":public_email", bold + @info[:public_email] + reg
		if @options[:loud]
			self.url_loud(@info[:public_url])
		else
			pprinthtn ":public_url", @info[:public_url]
		end
		self.whois(@info[:public_url]) if @options[:whois]
		pprinthttn ":repos", @info[:repos]
		pprinthttn ":gists", @info[:gists]
		pprinthtn ":followers", @info[:followers]
		pprinthtn ":follows", @info[:follows]

		if @info[:organizations] != nil
			printhn "\t:organizations"
			@info[:organizations].each do |x|
				printhttn x
			end
		end
		@commit_emails = self.emails()
		if @commit_emails != nil
			printhn "\t:emails"
			@commit_emails.each do |x|
				if @options[:haveibeenpwned]
					self.find_pwned(x, true)
				else
					printhttn bold + x + reg unless x.match('noreply.github')
				end
			end
			if @options[:haveibeenpwned] and @info[:public_email] and !@commit_emails.include? @info[:public_email]
				self.find_pwned(@info[:public_email], true)
			end
		end
		if @options[:stackoverflow]
			stackaccs = self.stackoverflow(nil)
			if @info[:display_name] and @info[:display_name] != "" and @info[:display_name] != @info[:username]
				stackaccs = stackaccs + self.stackoverflow(@info[:display_name])
			end
			if stackaccs != nil and stackaccs.length() != 0
				printhn "\t:potential stackoverflow accounts"
				count = 0
				stackaccs.each do |acc|
					break if count > 20
					stack_decide_bold(acc, @info)
					count = count + 1
				end
			end
		end
		printhn ""
		csv_output().each do |csv|
			@options[:csv_accounts].push(csv)
		end
	end

	def csv_output()
		output = []
		firstname = ""
		lastname = ""
		# Get all the emails
		emails = @commit_emails
		if @info[:public_email]
			emails.push(@info[:public_email])
		end
		if emails.length == 0
			return
		end
		# Parse their name into first and last
		if @info[:display_name]
			name = @info[:display_name].split
			firstname = name[0]
			if name.length != 1
				lastname = name[name.length - 1]
			end
		end
		emails.each do |email|
			output.push([firstname, lastname, email, @info[:username]].join(",")) if email.length > 1 and not email =~ /noreply.github/
		end
		output
	end

	def whois(url)
		return if url == nil or url == ""

		# Check whois is installed
		a = `which whois 2>&1`
		if a.include? "/"
		else
			STDERR.puts "whois utility not installed.\n"
			# Fail
			return
		end
		# Strip .*://
		url = url.sub(/^.*:\/\//, "")
		# Strip /.*$
		url = url.sub(/\/.*$/, "")
		# Potentially dangerous, but I think GitHub enforces proper URL formatting
		a = `mkdir report 2>&1 > /dev/null`
		a = `whois #{url} > report/whois_#{url}.txt`
		printhttn "report/whois_#{url}.txt created"
	end

	# This is a bit of an EyeWitness-type functionality
	def url_loud(url)
		# Filter out just the domain
		domain = url
		# thewizard, god of regex
		# Strip .*://
		domain = domain.sub(/^.*:\/\//, "")
		# Strip /.*$
		domain = domain.sub(/\/.*$/, "")
		# Check whether the domain is up
		up80 = false
		begin
			# Make a socket connection
			Addrinfo.tcp(domain, 80).connect({ :timeout => 3 }) { |s| 
				s.print "GET / HTTP/1.1\r\nHost: #{url}\r\n\r\n"
				a = s.read
			}
			up80 = true
		rescue => e
			# Domain is truly down
			up80 = false
		end
		up443 = false
		begin
			# Make a socket connection
			# This will fail because it's HTTPS but...
			sock = TCPSocket.new(domain, 443)
			ctx = OpenSSL::SSL::SSLContext.new
			ctx.set_params(verify_mode: OpenSSL::SSL::VERIFY_PEER)
			@socket = OpenSSL::SSL::SSLSocket.new(sock, ctx).tap do |socket|
				socket.sync_close = true
				socket.connect
			end
			up443 = true
		rescue => e
			# Domain is truly down
			up443 = false
		end
		if up80 and up443
			pprinthtn(":public_url", "#{url} (up - 80, 443)")
		elsif up80
			pprinthtn(":public_url", "#{url} (up - 80)")
		elsif up443
			pprinthtn(":public_url", "#{url} (up - 443)")
		else
			pprinthtn(":public_url", "#{url} (down)")
			return
		end
		# Firefox screenshots disabled
		# Screenshot
		#while `ps aux | grep firefox | grep -v grep`.include? "firefox"
		#	STDERR.puts "Please close Firefox and press enter to allow screenshots\n"
		#	a = STDIN.gets
		#end
		a = `mkdir report 2>&1 > /dev/null`
		#a = `firefox -no-remote -screenshot #{@username}_#{domain}.png #{url} 2>&1 > /dev/null && sleep .5 && mv #{@username}_#{domain}.png report/#{@username}_#{domain}.png`
		#printhttn("report/#{@username}_#{domain}.png created")
		begin
			page = HTTParty.get( url, headers: {
				'User-Agent' => '',
			} )
		rescue => e
			STDERR.puts "Network error:\n#{e}\n"
			return
		end
		File.write("report/#{@username}_url.html", page)
		printhttn "report/#{@username}_url.html created"
		if @options[:wl]
			@options[:pwHash].update(frequency_hash(page))
		end
	end

	def find_pwned(email, tobold)
		sleep(1.5) # Required for haveibeenpwned rate limiting
		# Should parse these out earlier
		return if email.match('noreply.github')
		return unless email.include? "@"
		api = "https://haveibeenpwned.com/api/v2/breachedaccount/"
		truncate = "?truncateResponse=true"
		bold = "\033[1;1m"
		reg = "\033[0;0m"
		begin
			breaches = HTTParty.get( "#{api}#{email}", headers: {
				'User-Agent' => UserAgent,
			} )
		rescue => e
			STDERR.puts "Network error:\n#{e}\n"
			return
		end
		if tobold
			printhttn bold + email + reg
		else
			printhttn email
		end
		return if breaches.code != 200
		return if breaches.body.include? "Page not found"
		breaches = JSON.parse(breaches.body)
		return unless breaches and breaches.length() != 0
		breaches.each do |breach|
			printhttn "\tBreached in #{breach["BreachDate"][0..3]}: #{breach["Name"]}"
		end
	end

	def stack_decide_bold(stack, git)
		bold = "\033[1;1m"
		reg = "\033[0;0m"
		tobold = false
		if stack[:location] and stack[:location] != "" and stack[:location] == git[:location]
			tobold = true
		elsif stack[:url] and stack[:url] != "" and stack[:url][/:\/\/(.*?)\/?$/, 0] == git[:public_url][/:\/\/(.*?)\/?$/, 0]
			tobold = true
		end
		printh bold if tobold
		printttn stack[:link]
		line2 = "\t"
		line2 = "\t#{stack[:location]} | " if stack[:location] != ""
		line2 = "#{line2}#{stack[:reputation]} rep"
		line2 = "#{line2} | #{stack[:url]}" if stack[:url] and stack[:url] != ""
		printhttn line2
		printhttn "\t#{stack[:bio]}" if stack[:bio] != "" if tobold
		printh reg if tobold
	end

	def bio()
		return @info[:bio] if @info[:bio]
	end
end

class Organization
	def initialize(org, auth)
		@org = org
		@page = 1
		@peopleurl = "https://api.github.com/orgs/#{org}/members?page="
		@reposurl = "https://api.github.com/orgs/#{org}/repos?page="
		@auth = auth
	end

	def people()
		people = []
		while true
			new = github_api_req("#{@peopleurl}#{@page}", @auth)
			if new.empty?
				break
			end
			new = JSON.parse(new)
			check_auth_resp(new)
			new.each do |x|
				people.push(x["login"])
			end
			@page = @page + 1
			break if @page > 5
		end
		people
	end

	def repos()
		repos = []
		page = 1
		while true
			resp = github_api_req("#{@reposurl}#{page}", @auth)
			if resp.empty? or resp == "[]"
				break
			end
			resp = JSON.parse(resp)
			check_auth_resp(resp)
			resp.each do |repo|
				next if repo["fork"]
				new = {
					:full_name => repo["full_name"],
					:repo => repo["name"],
					:url => repo["html_url"],
				}
				repos.push(new)
			end
			page = page + 1
		end
		repos
	end
end

class Gist
	def initialize(owner, gist_id, auth)
		@owner= owner
		@gist_id= gist_id
		@auth= auth
	end

	def url()
		"https://github.com/gists/#{@gist_id}"
	end

end

class Repo
	def initialize(owner, repo, auth)
		@owner = owner
		@repo = repo
		@auth = auth
		@page = 1
		@links = {
			:link => "https://api.github.com/repos/#{@owner}/#{@repo}",
			:contributors => "https://api.github.com/repos/#{@owner}/#{@repo}/contributors?page=",
			:readme => "https://api.github.com/repos/#{@owner}/#{@repo}/readme"
		}
	end

	def contributors()
		contributors = []
		while true
			resp = github_api_req("#{@links[:contributors]}#{@page}", @auth)
			new = JSON.parse(resp)
			if new.empty?
				break
			end
			check_auth_resp(new)
			new.each do |cont|
				contributors.push(cont["login"])
			end
			@page = @page + 1
		end
		contributors
	end

	def url()
		"https://github.com/#{@owner}/#{@repo}"
	end

	def wordlist(pwHash)
		printhn "Gathering words from #{@owner}/#{@repo}"
		resp = github_api_req(@links[:readme], @auth)
		resp = JSON.parse(resp)
	
		if !resp["message"].eql? "Not Found" # if there is a readme available
			readme = Base64.decode64(resp["content"])
			pwHash.update(frequency_hash(readme)) # update global password list
		end
		
		resp = github_api_req(@links[:link], @auth)
		resp = JSON.parse(resp)
		description = resp["description"]
		if description != nil
			pwHash.update(frequency_hash(description))
		end
	end
end

class Local
	def initialize(options)
		@options = options
		@committers = []
		@authors = []
		# TODO: cd and run git log on the path to make sure it's initialized
	end

	def scrape()
		# git log --pretty=format:"%an|%ae|%cn|%ce"
		printhn "Authors:"
		printhn `cd "#{@options[:local]}" && git log --pretty=format:"%an - %ae" | sort -u`
		printhn "Committers:"
		printhn `cd "#{@options[:local]}" && git log --pretty=format:"%cn - %ce" | sort -u`
		`cd "#{@options[:local]}" && git log --pretty=format:"%an|%ae|%cn|%ce"`.split(/\r?\n/).each do |line|
			format = line.split(/\|/)
			@authors.push({:name => format[0], :email => format[1]})
			@committers.push({:name => format[2], :email => format[3]})
		end
		@committers = @committers.uniq
		@authors = @authors.uniq
		csv_output().each do |csv|
			@options[:csv_accounts].push(csv)
		end
	end

	def csv_output()
		output = []
		@committers.each do |c|
			firstname = ""
			lastname = ""
			position = ""
			name = c[:name].split
			firstname = name[0]
			if name.length != 1
				lastname = name[name.length - 1]
			end
			output.push([firstname, lastname, c[:email], position].join(","))
		end
		@authors.each do |a|
			firstname = ""
			lastname = ""
			position = ""
			name = a[:name].split(" ")
			firstname = name[0]
			if name.length != 1
				lastname = name[name.length - 1]
			end
			output.push([firstname, lastname, a[:email], position].join(","))
		end
		output.uniq
	end

	def mine()
		regex = "PRIVATE KEY|A[A-Z]IA[A-Z]{8,}|[Pp][Aa][Ss]{2}[Ww][Oo]?[Rr]?[Dd].{,2}\\s*?[=:]|s3\.amazonaws\.com/|secret_key_base\\s*?[=:]"
		printn "Debug: creating report dir"
		a = `mkdir report 2>&1 > /dev/null`
		printn "Debug: creating mine.temp"
		a = `touch mine.temp`
		# Search through the repo
		currentlocation = `pwd`.rstrip
		printn "Debug: running git log command"
		printn "cd #{@options[:local]} && git log --pickaxe-regex -p --color-words -S #{regex} \":(exclude)*jquery*\" > #{currentlocation}/mine.temp && cd #{currentlocation}"
		`cd "#{@options[:local]}" && git log --pickaxe-regex -p --color-words -S "#{regex}" ":(exclude)*jquery*"> "#{currentlocation}/mine.temp" && cd "#{currentlocation}"`
		# Grab only the commit numbers, fine names, and the terms we're searching for
		filename = ""	# Filename
		line_num = 0
		printn "Debug: creating mined.temp"
		a = `touch mined.temp`
		a = `printf "Generated with git-user.rb, created by Patrick Hurd @ Coalfire Federal\n\n" > mined.temp`
		results = 0

		if( File.size("mine.temp") > 0 ) #does this file have any results
			File.readlines("mine.temp").each do |line|
				if ( line =~ /commit/ )
					File.write("mined.temp", line, File.size("mined.temp"), mode: "a")
				elsif ( line =~ /diff --git a/ )
					filename = line.rstrip
				elsif ( line =~ /@@ .*? @@/ )
					line_num = line[/\s\+(\d+),/, 0].to_i
				elsif ( line =~ /#{regex}/ ) # we found a match
					File.write("mined.temp", "#{filename[15..-1]}:#{line_num} #{line.strip}\n", File.size("mined.temp"), mode: "a")
					results += 1
					line_num += 1
				else
					line_num += 1
				end
			end
		else
			return
		end
		printh "Writing ./report/#{@options[:name]}_mined.html (results: #{results})\n"
		a = `cat mined.temp | aha -t #{@options[:name]} > "report/#{@options[:name]}_mined.html"`
		return
		# TODO: Figure out whether there's an upstream URL for the local repo and reference that
		# Post-processing
		betterhtml = ""
		File.readlines("report/#{@options[:name]}_mined.html").each do |line|
			if ( line =~ /olive;">commit / )
				commit = /commit ([0-9a-f]*)/.match(line).captures
				commit = commit[0]
				if ( repo_url =~ /gist.github.com/ )
					betterhtml += "<span style=\"color:olive;\">commit <a href=\"#{repo_url}/#{commit}\">#{commit}</a></span>\n"
				else
					betterhtml += "<span style=\"color:olive;\">commit <a href=\"#{repo_url}/commit/#{commit}\">#{commit}</a></span>\n"
				end
			else
				betterhtml += line
			end
		end
		File.write("report/#{repo}_mined.html", betterhtml)
		a = `rm mine.temp mined.temp`
	end
end

def frequency_hash(string)
	words = string.split(' ')
	frequency = Hash.new(0)
	words.each { |word| frequency[word.downcase] += 1 }
	frequency.delete_if { |key, value| value < 2 } # if the word is used less than 2 times, delete it
	frequency.delete_if { |key, value| key.length < 4 }# if the word is shorter than 4 characters, delete it
	frequency.each do |key,value|
		if key =~ /^[a-zA-Z0-9]*$/
			#STDERR.puts "KEY: #{key} matches"
		else
			frequency.delete(key)
			#STDERR.puts "KEY: #{key} deleted."
		end
	end
	frequency
end

def mine_repo(repo_url)
	regex = "PRIVATE KEY|A[A-Z]IA[A-Z]{8,}|[Pp][Aa][Ss]{2}[Ww][Oo]?[Rr]?[Dd].{,2}\\s*?[=:]|s3\.amazonaws\.com/|secret_key_base\\s*?[=:]"
	repo = repo_url.scan(/\/([A-Za-z0-9\-_\.]*)$/)[0][0]

	a = `mkdir report 2>&1 > /dev/null`
	# Clone repo
	a = `git clone #{repo_url} 2>&1`
	a = `touch mine.temp`
	# Search through the repo
	`cd #{repo} && git log --pickaxe-regex -p --color-words -S "#{regex}" ":(exclude)*jquery*" > ../mine.temp && cd .. && rm -rf #{repo}`
	# Grab only the commit numbers, fine names, and the terms we're searching for
	filename = ""	# Filename
	line_num = 0
	a = `touch mined.temp`
	a = `printf "Generated with git-user.rb, created by Patrick Hurd @ Coalfire Federal\n\n" > mined.temp`
	results=0

	if(File.size("mine.temp")>0) #does this file have any results
		File.readlines("mine.temp").each do |line|
			if ( line =~ /commit/ )
				File.write('mined.temp', line, File.size('mined.temp'), mode: 'a')
				#a = `echo "#{line}" >> mined.temp`
			elsif ( line =~ /diff --git a/ )
				filename = line.rstrip
			elsif ( line =~ /@@ .*? @@/ )
				line_num = line[/\s\+(\d+),/, 0].to_i
			elsif ( line =~ /#{regex}/ ) # we found a match
				File.write('mined.temp', "#{filename[15..-1]}:#{line_num} #{line.strip}\n", File.size('mined.temp'), mode: 'a')
				#a = `echo "#{filename[15..-1]}:#{line_num} #{line.strip}" >> mined.temp`
				results+=1
				line_num += 1
			else
				line_num += 1
			end
		end
		printh "Writing ./report/#{repo}_mined.html (results: #{results})\n"
		a = `cat mined.temp | aha -t #{repo} > report/#{repo}_mined.html`
		# Post-processing
		betterhtml = ""
		File.readlines("report/#{repo}_mined.html").each do |line|
			if ( line =~ /olive;">commit / )
				commit = /commit ([0-9a-f]*)/.match(line).captures
				commit = commit[0]
				if ( repo_url =~ /gist.github.com/ )
					betterhtml += "<span style=\"color:olive;\">commit <a href=\"#{repo_url}/#{commit}\">#{commit}</a></span>\n"
				else
					betterhtml += "<span style=\"color:olive;\">commit <a href=\"#{repo_url}/commit/#{commit}\">#{commit}</a></span>\n"
				end
			else
				betterhtml += line
			end
		end
		File.write("report/#{repo}_mined.html", betterhtml)
	end
	a = `rm mine.temp mined.temp`
end

options = { :pwHash => pwHash }

OptionParser.new do |parser|
	parser.banner = "Usage: git-user.rb [options]"

	parser.on("-h", "--help", "Show this help banner") do ||
		puts parser
		print "\n"
		print "Tip: --repo needs either -o or -u to be set\n\n"
		print "Tip: --extra_checks needs -a or -t to make authenticated API calls\n\n"
		print "Tip: --pwned and --csv needs -e to be set to ensure your scope is correct\n\n"
		print "Created by Patrick Hurd @ Coalfire Federal\n"
		exit
	end

	# Targetting options
	parser.on("-u", "--user USERNAME", "User to gather info from") do |v|
		options[:user] = v
	end
	parser.on("-o", "--organization ORGANIZATION", "Organization to scrape") do |v|
		options[:org] = v
	end
	parser.on("-r", "--repo REPO", "The repo whom's contributors to scrape") do |v|
		options[:repo] = v
	end
	parser.on("--local ABSOLUTE_PATH", "Perform scrape on a repo local to your filesystem") do |v|
		options[:local] = v
	end
	parser.on("--name NAME", "Name to refer to a --local repo in report filenames") do |v|
		options[:name] = v
	end

	# Authentication options
	parser.on("-a", "--auth", "Authenticate with HTTP basic auth") do ||
		options[:auth] = true
	end
	parser.on("-t", "--token TOKEN", "Use specified GitHub personal access token") do |v|
		options[:token] = v
	end

	# Scraper activities
	parser.on("-s", "--stackoverflow", "Try to find users' accounts on StackOverflow") do ||
		options[:stackoverflow] = true
	end
	parser.on("-p", "--pwned", "Search for relevant data breaches using haveibeenpwned") do ||
		options[:haveibeenpwned] = true
	end
	parser.on("-e", "--extra_checking", "Do extra checking on email addresses") do ||
		options[:extra_checking] = true
	end
	parser.on("-m", "--mine", "Mine the repo or user/organization's repos for secrets") do ||
		options[:mine] = true
	end
	parser.on("--whois", "Perform whois lookup on domains found in profile information") do ||
		options[:whois] = true
	end
	parser.on("-l", "--loud", "Perform active recon on users (scrape their personal site)") do ||
		options[:loud] = true
	end

	# Output options
	parser.on("--html", "Output main report to an HTML document") do ||
		options[:html] = true
	end
	parser.on("-w", "--wordlist", "Generate wordlist for use in password attacks") do ||
		options[:wl] = true
	end
	parser.on("-c", "--csv", "Export discovered accounts to a GoPhish-importable CSV file") do ||
		options[:csv] = true
	end
end.parse!

logo = <<-LOGO
    ___       ___       ___       ___       ___       ___       ___
   /\\  \\     /\\  \\     /\\  \\     /\\__\\     /\\  \\     /\\  \\     /\\  \\
  /  \\  \\   _\\ \\  \\    \\ \\  \\   / / _/_   /  \\  \\   /  \\  \\   /  \\  \\
 / /\\ \\__\\ /\\/  \\__\\   /  \\__\\ / /_/\\__\\ /\\ \\ \\__\\ /  \\ \\__\\ /  \\ \\__\\
 \\ \\ \\/__/ \\  /\\/__/  / /\\/__/ \\ \\/ /  / \\ \\ \\/__/ \\ \\ \\/  / \\,   /  /
  \\  /  /   \\ \\__\\    \\/__/     \\  /  /   \\  /  /   \\ \\/  /   | \\/__/
   \\/__/     \\/__/               \\/__/     \\/__/     \\/__/     \\|__|
   	      	
Created by Patrick Hurd @ Coalfire Federal
LOGO

options[:csv_accounts] = []
if options[:csv] and !options[:extra_checking] and !options[:local]
	print "Extra checking must be enabled with -e to use -c.\n"
	print "This helps ensure you do not get incorrect results..\n\n"
	exit
end
if options[:haveibeenpwned] and !options[:extra_checking]
	print "Extra checking must be enabled with -e to use -p.\n"
	print "This ensures you do not reach beyond the intended scope.\n\n"
	exit
end
if options[:extra_checking] and !(options[:auth] or options[:token])
	print "GitHub basic authentication must be enabled with -a to use -e."
	print "Extra checking will chew through your unauthenticated API limit.\n\n"
	exit
end
if options[:mine] and !`which aha`.include? "/aha"
	print "git-user.rb uses aha to generate mine reports."
	print "Install aha with:"
	print "sudo apt install aha -y"
	exit
end

if options[:auth]
	print "Using HTTP basic auth\n"
	print "Enter your username: "
	username = gets.chomp
	print "Enter your password: "
	password = STDIN.noecho(&:gets).chomp
	print "\n"
	options[:auth] = { :username => username, :password => password }
elsif options[:token]
	options[:auth] = { :token => options[:token] }
else
	options[:auth] = { :username => "", :password => "" }
end

if options[:repo]
	owner = options[:org] ? options[:org] : options[:user]
	if owner == nil
		print "\nYou need to specify the user or organization who owns the repo.\n\n"
		exit
	end
	printh logo + "\ngit-user.rb report for https://github.com/" + owner + "/" + options[:repo] + "\n\n"
	repo = Repo.new(owner, options[:repo], options[:auth])
	repo.contributors().each do |person|
		options[:user] = person
		user = User.new(options)
		user.get_info()
		user.print_info()
	end
	if options[:mine]
		printhn "Mining #{owner}/#{options[:repo]}"
		STDERR.puts "Warning: terminating git-user.rb while mining may leave data fragments in your working directory."
		mine_repo(repo.url())

	end
	if options[:wl]
		repo.wordlist(pwHash)
	end
elsif options[:user]
	printh logo + "\n"
	user = User.new(options)
	user.get_info()
	user.print_info()
	if options[:mine]
		STDERR.puts "Warning: terminating git-user.rb while mining may leave data fragments in your working directory."
		user.repos().each do |repo|
			printhn "Mining #{options[:user]}/#{repo[:repo]}"
			mine_repo(repo[:url])

		end
		user.gists().each do |gist|
			printhn "Mining #{options[:user]}/#{gist[:id]}"
			mine_repo(gist[:url])
		end
	end
	if options[:wl]
		printhn "Generating Password Wordlist\n"
		user.repos().each do |repo|
			repo = Repo.new(options[:user], repo[:repo], options[:auth])
			repo.wordlist(pwHash)
		end
		pwHash.update(frequency_hash(user.bio()))
	end
elsif options[:org]
	printh logo + "\ngit-user.rb report for https://github.com/" + options[:org] + "\n\n"
	org = Organization.new(options[:org], options[:auth])
	org.people().each do |person|
		options[:user] = person
		user = User.new(options)
		user.get_info()
		user.print_info()
	end
	if options[:mine]
		STDERR.puts "Warning: terminating git-user.rb while mining may leave data fragments in your working directory."
		org.repos().each do |repo|
			printhn "Mining #{options[:org]}/#{repo[:repo]}"
			mine_repo(repo[:url])
		end
	end
	if options[:wl]
		printhn "\nGenerating Password Wordlist\n\n"
		org.repos().each do |repo|
			repo = Repo.new(options[:user], repo[:repo], options[:auth])
			repo.wordlist(pwHash)
		end
	end
elsif options[:local]
	printh logo + "\ngit-user.rb report for " + options[:local] + " - " + options[:name] + "\n\n"
	if not options[:name]
		STDERR.puts "A --name is required for --local repos"
	end
	l = Local.new(options)
	l.scrape()
	if options[:mine]
		l.mine()
	end
else
	print `ruby #{$0} --help`
end

if options[:haveibeenpwned]
	printh "Breached account data courtesy of https://haveibeenpwned.com\n"
end

if options[:html]
	HTMLOut << HTMLEnd
	name = options[:name] ? options[:name] : options[:org] ? options[:org] : options[:user]
	File.write("./report_#{name}.html", HTMLOut)
end

if options[:wl]
	pwHash=pwHash.sort {|x,y| x[1]<=>y[1]}

	pwHash = Hash[pwHash.reverse]
	a = `mkdir report 2>&1 > /dev/null`
	File.open("./report/wordlist.txt", "w") do |file|
		pwHash.keys.each do |key|
			file.write("#{key}\n")
		end
		printhn("Generated wordlist ./report/wordlist.txt")
	end
end

if options[:csv]
	name = options[:name] ? options[:name] : options[:org] ? options[:org] : options[:user]
	a = `mkdir report 2>&1 > /dev/null`
	File.open("./report/#{name}_gophish.csv", "w") do |file|
		file.write("First Name,Last Name,Email,Position\n")
		options[:csv_accounts].each do |account|
			file.write("#{account}\n")
		end
		printhn("Generated GoPhish CSV ./report/#{name}_gophish.csv")
	end
end
