FROM ruby:2.5.1
RUN apt-get update -qq && apt-get install -y build-essential libpq-dev nodejs
ENV APP_PATH /app
RUN mkdir $APP_PATH
WORKDIR $APP_PATH
ADD rails/ $APP_PATH 
RUN cd $APP_PATH \
    && echo "gem 'therubyracer', platforms: :ruby" >> Gemfile \
    && bundle update mimemagic \
    && bundle install 
WORKDIR $APP_PATH/
ADD start_rails.sh $APP_PATH
RUN chmod +x start_rails.sh
EXPOSE 3000
ENTRYPOINT ["./start_rails.sh"]
