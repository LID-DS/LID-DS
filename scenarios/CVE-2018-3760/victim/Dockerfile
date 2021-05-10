FROM vulhub/rails:5.0.7

RUN apt-get update && apt-get install -y git nodejs

WORKDIR /usr/src


RUN rm -r /usr/src/blog
RUN git clone https://github.com/PrimeLens/Rails5-app-example-with-MVC-and-CRUD blog

WORKDIR /usr/src/blog

# RUN rm /usr/src/blog/Gemfile
COPY Gemfile /usr/src/blog/
RUN bundle install

RUN bundle exec rake db:migrate

EXPOSE 3000

CMD ["rails", "server", "-b", "0.0.0.0", "-p", "3000"]