FROM ruby:2.5.1
RUN apt-get update -qq && apt-get install -y build-essential libpq-dev nodejs
ENV APP_PATH /app
RUN mkdir $APP_PATH
WORKDIR $APP_PATH
ADD CVE-2019-5418/ .
RUN ls
RUN cd $APP_PATH/demo/ \
    && echo "gem 'therubyracer', platforms: :ruby" >> Gemfile \
    && bundle update mimemagic \
    && bundle install 
WORKDIR $APP_PATH/demo/
EXPOSE 3000
CMD ["rails","s", "-b", "0.0.0.0"]
#ENTRYPOINT ["/bin/bash"]


