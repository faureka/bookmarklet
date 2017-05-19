import React from 'react';
import {render} from 'react-dom';

class InlineForm extends React.Component {

    componentWillReceiveProps() {

    }

    componentDidMount() {

    }

    render() {
        return (
            <div className={this.props.style}>
                <form id={this.props.formId} className="form-inline">
                <div className="form-group mx-md-3">
                    <label htmlFor={this.props.inputId} className="sr-only">Url</label>
                    <input type="text" name={this.props.inputId} className="form-control" id={this.props.inputId} placeholder={this.props.inputId} />
                </div>
                <button type={this.props.buttonType} className="btn btn-primary"> {this.props.buttonName} </button>
                </form>
            </div>
        );
    }
}

export default InlineForm;