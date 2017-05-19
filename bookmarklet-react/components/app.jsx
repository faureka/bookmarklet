import React from 'react';
import { render } from 'react-dom';
import InlineForm from './InlineForm.jsx';
import ListView from '../container/ListView.jsx';


export default class App extends React.Component {
  render() {
    return (
        <div className="container">
          <div className="row">
            <InlineForm 
              style="col-md-6 float-md-left"
              formId="urlpost"
              inputId="url"
              buttonName="Submit"
              buttonType="submit"
            />
            <InlineForm
              style="col-md-6 float-md-right"
              formId="search"
              inputId="query"
              buttonName="Search"
              buttonType="submit"
            />
          </div>
          <ListView />
        </div>
      );
  }
}