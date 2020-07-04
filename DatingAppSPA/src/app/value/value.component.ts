import { Component, OnInit, ErrorHandler } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { error } from '@angular/compiler/src/util';

@Component({
  selector: 'app-value',
  templateUrl: './value.component.html',
  styleUrls: ['./value.component.css']
})
export class ValueComponent implements OnInit {

  values: any;

  constructor(private Http: HttpClient) { }

  ngOnInit() {
    this.getValues();
  }

  getValues(){
    this.Http.get('http://localhost:5000/api/values').subscribe(response => {
      this.values = response;
    }, error =>{
    console.log(error);
    });
  }

}
